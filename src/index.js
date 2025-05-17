import express from "express";
import { google } from "googleapis";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const frontendUrl = process.env.FRONTEND_URL || "http://localhost:5173";
// Google OAuth2 configuration
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLOUD_CLIENT_ID,
  process.env.GOOGLE_CLOUD_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// Enable CORS for all routes
app.use(
  cors({
    origin: frontendUrl, // Vite's default port
    credentials: true, // Allow cookies
  })
);

// Parse JSON bodies and cookies
app.use(express.json());
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

  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: scopes,
    include_granted_scopes: true,
    prompt: "consent", // Force consent screen to ensure we get refresh token
  });

  res.json({ url: authUrl });
});

// Handle Google OAuth callback
app.get("/auth/callback", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).send("Missing authorization code");
  }

  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Set tokens as HTTP-only cookies
    res.cookie("accessToken", tokens.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 3600000, // 1 hour
      domain: "localhost", // Important for local development
      path: "/",
    });

    res.cookie("refreshToken", tokens.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 30 * 24 * 3600000, // 30 days
      domain: "localhost", // Important for local development
      path: "/",
    });

    // Redirect to frontend success page
    res.redirect(`${frontendUrl}/auth/success`);
  } catch (error) {
    console.error("Error during OAuth callback:", error);
    res.status(500).send("Authentication failed");
  }
});

// Refresh access token
app.post("/api/auth/refresh", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).send("No refresh token provided");
  }

  try {
    oauth2Client.setCredentials({
      refresh_token: refreshToken,
    });

    const { credentials } = await oauth2Client.refreshAccessToken();
    res.json({ accessToken: credentials.access_token });
  } catch (error) {
    console.error("Error refreshing token:", error);
    res.status(401).send("Failed to refresh token");
  }
});

// Check auth status
app.get("/api/auth/status", (req, res) => {
  if (!req.cookies) {
    return res.status(401).send();
  }

  const accessToken = req.cookies.accessToken;
  const refreshToken = req.cookies.refreshToken;

  if (accessToken && refreshToken) {
    res.status(200).send();
  } else {
    res.status(401).send();
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

    // Update the file content
    const response = await drive.files.update({
      fileId: req.params.id,
      media: {
        mimeType: fileMetadata.data.mimeType,
        body: content
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
      fields: "name, mimeType",
    });

    // Check if file is text-based
    const mimeType = fileMetadata.data.mimeType;
    const isTextFile =
      mimeType.startsWith("text/") ||
      mimeType.includes("javascript") ||
      mimeType.includes("json") ||
      mimeType.includes("xml") ||
      mimeType.includes("markdown") ||
      mimeType.includes("code");

    if (!isTextFile) {
      return res
        .status(400)
        .json({
          error: "File type not supported. Only text-based files are allowed.",
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

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
