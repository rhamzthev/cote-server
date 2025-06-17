import express from "express";
import { google } from "googleapis";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import https from "https";
import http from "http";
import fs from "fs";
import { Readable } from "stream";

dotenv.config();

const app = express();
const isProduction = process.env.NODE_ENV === "production";
const frontendUrl = isProduction 
  ? "https://cote.rhamzthev.com"
  : "http://localhost:5173";

// Google OAuth2 configuration
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLOUD_CLIENT_ID,
  process.env.GOOGLE_CLOUD_CLIENT_SECRET,
  isProduction 
    ? "https://api.cote.rhamzthev.com/auth/callback"
    : "http://localhost:8080/auth/callback"
);

// Enable CORS for all routes
app.use(
  cors({
    origin: frontendUrl,
    credentials: true,
  })
);

// Parse JSON bodies and cookies
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());

// Ping endpoint for health checks
app.get("/ping", (req, res) => {
  res.json({ pong: true, timestamp: new Date().toISOString() });
});

//#region UNAUTHORIZED ROUTES
// Generate Google OAuth URL with Drive scopes
app.get("/auth/google/url", (req, res) => {
  const scopes = [
    "https://www.googleapis.com/auth/drive.file", // Access to files created by the app
    "https://www.googleapis.com/auth/drive.install", // Access to install the app
  ];

  // Get the return URL from query params, default to frontend root
  const returnUrl = req.query.returnUrl || '/';

  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: scopes,
    include_granted_scopes: true,
    prompt: "consent", // Force consent screen to ensure we get refresh token
    state: returnUrl // Store the return URL in state parameter
  });

  res.json({ url: authUrl });
});

// Handle Google OAuth callback
app.get("/auth/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).json({ error: "Missing authorization code" });
  }

  // Validate state parameter to prevent CSRF attacks
  if (!state) {
    return res.status(400).json({ error: "Missing state parameter" });
  }

  try {
    const { tokens } = await oauth2Client.getToken(code);
    
    // Validate tokens
    if (!tokens.access_token || !tokens.refresh_token) {
      throw new Error("Invalid token response from Google");
    }

    oauth2Client.setCredentials(tokens);

    // Set tokens as HTTP-only cookies with appropriate domain
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      domain: process.env.NODE_ENV === "production" ? ".rhamzthev.com" : "localhost",
    };

    res.cookie("accessToken", tokens.access_token, {
      ...cookieOptions,
      maxAge: 3600000, // 1 hour
    });

    res.cookie("refreshToken", tokens.refresh_token, {
      ...cookieOptions,
      maxAge: 30 * 24 * 3600000, // 30 days
    });

    // Set security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

    // Redirect back to the original URL stored in state parameter
    const returnUrl = state || '/';
    res.redirect(`${frontendUrl}${returnUrl}`);
  } catch (error) {
    console.error("Error during OAuth callback:", error);
    res.status(500).json({ 
      error: "Authentication failed",
      message: process.env.NODE_ENV === "production" ? "Internal server error" : error.message
    });
  }
});

// Refresh access token
app.post("/api/auth/refresh", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: "No refresh token found" });
  }

  try {
    oauth2Client.setCredentials({
      refresh_token: refreshToken,
    });

    const { credentials } = await oauth2Client.refreshAccessToken();
    
    if (!credentials.access_token) {
      throw new Error("Invalid token response from Google");
    }

    // Set the new access token cookie with appropriate domain
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      domain: process.env.NODE_ENV === "production" ? ".rhamzthev.com" : "localhost",
      maxAge: 3600000, // 1 hour
    };

    res.cookie("accessToken", credentials.access_token, cookieOptions);

    // Set security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

    res.json({ success: true });
  } catch (error) {
    console.error("Error refreshing token:", error);
    res.status(401).json({ 
      error: "Failed to refresh token",
      message: process.env.NODE_ENV === "production" ? "Authentication failed" : error.message
    });
  }
});

// Check auth status
app.get("/api/auth/status", (req, res) => {
  if (!req.cookies) {
    return res.status(401).json({ error: "No cookies found" });
  }

  const accessToken = req.cookies.accessToken;
  const refreshToken = req.cookies.refreshToken;

  if (accessToken && refreshToken) {
    res.status(200).send();
  } else {
    res.status(401).json({ error: "No access token or refresh token found" });
  }
});

// Get current user
app.get("/api/auth/user", async (req, res) => {
  const accessToken = req.cookies.accessToken;

  if (!accessToken) {
    return res.status(401).json({ error: "No access token found" });
  }

  try {
    oauth2Client.setCredentials({ access_token: accessToken });
    
    const oauth2 = google.oauth2({
      version: 'v2',
      auth: oauth2Client
    });

    // Get user info from Google
    const userInfo = await oauth2.userinfo.get();
    
    res.json({
      id: userInfo.data.id,
      email: userInfo.data.email,
      name: userInfo.data.name,
      picture: userInfo.data.picture
    });
  } catch (error) {
    console.error("Error fetching user info:", error);
    res.status(500).json({ 
      error: "Failed to fetch user information",
      message: process.env.NODE_ENV === "production" ? "Internal server error" : error.message
    });
  }
});

// Logout endpoint
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.status(200).send();
});

//#endregion

//#region AUTHORIZED ROUTES

// Get file star status
app.get("/api/drive/files/:id/star", async (req, res) => {
  const accessToken = req.cookies.accessToken;

  if (!accessToken) {
    return res.status(401).send("No access token found");
  }

  try {
    oauth2Client.setCredentials({ access_token: accessToken });
    
    const drive = google.drive({
      version: "v3",
      auth: oauth2Client,
    });

    const response = await drive.files.get({
      fileId: req.params.id,
      fields: "starred"
    });

    res.json({ starred: response.data.starred });
  } catch (error) {
    console.error("Error getting file star status:", error);
    if (error.code === 404) {
      res.status(404).json({ error: "File not found" });
    } else {
      res.status(500).json({ error: "Failed to get file star status" });
    }
  }
});

// Toggle file star status
app.put("/api/drive/files/:id/star", async (req, res) => {
  const accessToken = req.cookies.accessToken;

  if (!accessToken) {
    return res.status(401).send("No access token found");
  }

  try {
    oauth2Client.setCredentials({ access_token: accessToken });
    
    const drive = google.drive({
      version: "v3",
      auth: oauth2Client,
    });

    // First get current star status
    const currentStatus = await drive.files.get({
      fileId: req.params.id,
      fields: "starred"
    });

    // Toggle the star status
    const response = await drive.files.update({
      fileId: req.params.id,
      requestBody: {
        starred: !currentStatus.data.starred
      },
      fields: "starred"
    });

    res.json({ starred: response.data.starred });
  } catch (error) {
    console.error("Error toggling file star status:", error);
    if (error.code === 404) {
      res.status(404).json({ error: "File not found" });
    } else {
      res.status(500).json({ error: "Failed to toggle file star status" });
    }
  }
});

// Update file content
app.put("/api/drive/files/:id/content", async (req, res) => {
  const accessToken = req.cookies.accessToken;

  if (!accessToken) {
    return res.status(401).send("No access token found");
  }

  const { content } = req.body;
  if (content === undefined) {
    return res.status(400).json({ error: "Content is required" });
  }

  try {
    oauth2Client.setCredentials({ access_token: accessToken });
    
    const drive = google.drive({
      version: "v3",
      auth: oauth2Client,
    });

    // First get the file metadata to check mime type
    const fileMetadata = await drive.files.get({
      fileId: req.params.id,
      fields: "mimeType",
    });

    // Create a readable stream from the content
    const contentStream = new Readable();
    contentStream.push(content);
    contentStream.push(null);

    // Update the file content using streams
    const response = await drive.files.update({
      fileId: req.params.id,
      media: {
        mimeType: fileMetadata.data.mimeType,
        body: contentStream
      },
      fields: "id, name, mimeType"
    });

    res.json({
      id: response.data.id,
      name: response.data.name,
      mimeType: response.data.mimeType
    });
  } catch (error) {
    console.error("Error updating file content:", error);
    if (error.code === 404) {
      res.status(404).json({ error: "File not found" });
    } else {
      res.status(500).json({ error: "Failed to update file content" });
    }
  }
});

// Rename file
app.put("/api/drive/files/:id", async (req, res) => {
  const accessToken = req.cookies.accessToken;

  if (!accessToken) {
    return res.status(401).send("No access token found");
  }

  const { filename } = req.body;
  if (!filename) {
    return res.status(400).json({ error: "Filename is required" });
  }

  try {
    oauth2Client.setCredentials({ access_token: accessToken });
    
    const drive = google.drive({
      version: "v3",
      auth: oauth2Client,
    });

    const response = await drive.files.update({
      fileId: req.params.id,
      requestBody: {
        name: filename
      },
      fields: "id, name"
    });

    res.json({
      id: response.data.id,
      name: response.data.name
    });
  } catch (error) {
    console.error("Error renaming file:", error);
    if (error.code === 404) {
      res.status(404).json({ error: "File not found" });
    } else {
      res.status(500).json({ error: "Failed to rename file" });
    }
  }
});

// Get file content
app.get("/api/drive/files/:id", async (req, res) => {
  const accessToken = req.cookies.accessToken;

  if (!accessToken) {
    return res.status(401).send("No access token found");
  }

  try {
    oauth2Client.setCredentials({ access_token: accessToken });

    const drive = google.drive({
      version: "v3",
      auth: oauth2Client,
    });

    // First get the file metadata to check mime type and name
    const fileMetadata = await drive.files.get({
      fileId: req.params.id,
      fields: "name, mimeType, starred",
    });

    // Check if file is text-based
    const mimeType = fileMetadata.data.mimeType;
    
    // Map of supported MIME types
    const supportedMimeTypes = {
      // Text files
      'text/plain': true,
      'text/markdown': true,
      'text/x-markdown': true,
      'text/x-c': true,
      'text/x-c++': true,
      'text/x-java': true,
      'text/x-python': true,
      'text/x-php': true,
      'text/x-ruby': true,
      'text/x-swift': true,
      'text/x-go': true,
      'text/x-rust': true,
      'text/x-kotlin': true,
      'text/x-scala': true,
      'text/x-yaml': true,
      'text/x-toml': true,
      'text/x-ini': true,
      'text/x-shellscript': true,
      'text/x-sql': true,
      'text/x-html': true,
      'text/x-css': true,
      'text/x-javascript': true,
      'text/x-typescript': true,
      'text/x-coffeescript': true,
      'text/x-clojure': true,
      'text/x-dart': true,
      'text/x-elixir': true,
      'text/x-fsharp': true,
      'text/x-graphql': true,
      'text/x-handlebars': true,
      'text/x-hcl': true,
      'text/x-julia': true,
      'text/x-less': true,
      'text/x-lua': true,
      'text/x-objective-c': true,
      'text/x-pascal': true,
      'text/x-perl': true,
      'text/x-powershell': true,
      'text/x-protobuf': true,
      'text/x-pug': true,
      'text/x-r': true,
      'text/x-redis': true,
      'text/x-rst': true,
      'text/x-sass': true,
      'text/x-scss': true,
      'text/x-sol': true,
      'text/x-sparql': true,
      'text/x-st': true,
      'text/x-tcl': true,
      'text/x-twig': true,
      'text/x-vb': true,
      'text/x-xml': true,
      'text/x-yaml': true,
      'text/x-wgsl': true,
      'text/x-verilog': true,
      'text/x-systemverilog': true,
      'text/x-mips': true,
      'text/x-msdax': true,
      'text/x-mysql': true,
      'text/x-pgsql': true,
      'text/x-redshift': true,
      'text/x-sql': true,
      'text/x-qsharp': true,
      'text/x-razor': true,
      'text/x-sb': true,
      'text/x-scheme': true,
      'text/x-aes': true,
      'text/x-pla': true,
      'text/x-postiats': true,
      'text/x-powerquery': true,
      'text/x-mdx': true,
      'text/x-liquid': true,
      'text/x-m3': true,
      'text/x-lexon': true,
      'text/x-ecl': true,
      'text/x-cameligo': true,
      'text/x-pascaligo': true,
      'text/x-bicep': true,
      'text/x-azcli': true,
      'text/x-bat': true,
      'text/x-csp': true,
      'text/x-cypher': true,
      'text/x-dockerfile': true,
      'text/x-flow9': true,
      'text/x-freemarker2': true,
      'text/x-abap': true,
      'text/x-apex': true,
      
      // Application types
      'application/javascript': true,
      'application/json': true,
      'application/xml': true,
      'application/x-httpd-php': true,
      'application/x-python': true,
      'application/x-ruby': true,
      'application/x-java': true,
      'application/x-csharp': true,
      'application/x-typescript': true,
      'application/x-ld+json': true,
      'application/x-yaml': true,
      'application/x-toml': true,
      'application/x-ini': true,
      'application/x-shellscript': true,
      'application/x-sql': true,
      'application/x-html': true,
      'application/x-css': true,
      'application/x-go': true,
      'application/x-rust': true,
      'application/x-kotlin': true,
      'application/x-scala': true,
      'application/x-swift': true,
      'application/x-dart': true,
      'application/x-elixir': true,
      'application/x-fsharp': true,
      'application/x-graphql': true,
      'application/x-handlebars': true,
      'application/x-hcl': true,
      'application/x-julia': true,
      'application/x-less': true,
      'application/x-lua': true,
      'application/x-objective-c': true,
      'application/x-pascal': true,
      'application/x-perl': true,
      'application/x-powershell': true,
      'application/x-protobuf': true,
      'application/x-pug': true,
      'application/x-r': true,
      'application/x-redis': true,
      'application/x-rst': true,
      'application/x-sass': true,
      'application/x-scss': true,
      'application/x-sol': true,
      'application/x-sparql': true,
      'application/x-st': true,
      'application/x-tcl': true,
      'application/x-twig': true,
      'application/x-vb': true,
      'application/x-xml': true,
      'application/x-yaml': true,
      'application/x-wgsl': true,
      'application/x-verilog': true,
      'application/x-systemverilog': true,
      'application/x-mips': true,
      'application/x-msdax': true,
      'application/x-mysql': true,
      'application/x-pgsql': true,
      'application/x-redshift': true,
      'application/x-sql': true,
      'application/x-qsharp': true,
      'application/x-razor': true,
      'application/x-sb': true,
      'application/x-scheme': true,
      'application/x-aes': true,
      'application/x-pla': true,
      'application/x-postiats': true,
      'application/x-powerquery': true,
      'application/x-mdx': true,
      'application/x-liquid': true,
      'application/x-m3': true,
      'application/x-lexon': true,
      'application/x-ecl': true,
      'application/x-cameligo': true,
      'application/x-pascaligo': true,
      'application/x-bicep': true,
      'application/x-azcli': true,
      'application/x-bat': true,
      'application/x-csp': true,
      'application/x-cypher': true,
      'application/x-dockerfile': true,
      'application/x-flow9': true,
      'application/x-freemarker2': true,
      'application/x-abap': true,
      'application/x-apex': true,
    };

    const isTextFile = supportedMimeTypes[mimeType] || mimeType.startsWith('text/');

    if (!isTextFile) {
      return res
        .status(400)
        .json({
          error: "Unsupported file type",
          details: `The file type "${mimeType}" is not supported. This editor only supports text-based files and source code files.`,
          mimeType: mimeType,
          supportedTypes: Object.keys(supportedMimeTypes)
        });
    }

    // Get the file contents
    const response = await drive.files.get(
      {
        fileId: req.params.id,
        alt: "media",
      },
      {
        responseType: "text",
      }
    );

    res.json({
      filename: fileMetadata.data.name,
      content: response.data,
      starred: fileMetadata.data.starred
    });
  } catch (error) {
    console.error("Error fetching file:", error);
    if (error.code === 404) {
      res.status(404).json({ error: "File not found" });
    } else {
      res.status(500).json({ error: "Failed to fetch file" });
    }
  }
});

//#endregion

// SSL Configuration
let sslOptions;
if (isProduction) {
  sslOptions = {
    key: fs.readFileSync("/etc/letsencrypt/live/api.cote.rhamzthev.com/privkey.pem"),
    cert: fs.readFileSync("/etc/letsencrypt/live/api.cote.rhamzthev.com/fullchain.pem"),
  };
} else {
  sslOptions = {
    key: fs.readFileSync("./localhost/localhost-key.pem"),
    cert: fs.readFileSync("./localhost/localhost.pem"),
  };
}

// Create HTTP and HTTPS servers
const httpServer = http.createServer(app);
const httpsServer = https.createServer(sslOptions, app);

// Start servers based on environment
if (isProduction) {
  // Production: Listen on both HTTP and HTTPS
  httpServer.listen(80, () => {
    console.log(`HTTP Server running on port 80`);
  });

  httpsServer.listen(443, () => {
    console.log(`HTTPS Server running on port 443`);
  });
} else {
  // Development: Listen on both HTTP and HTTPS
  httpServer.listen(8080, () => {
    console.log(`Development HTTP server running on port 8080`);
  });
  
  httpsServer.listen(8443, () => {
    console.log(`Development HTTPS server running on port 8443`);
  });
}
