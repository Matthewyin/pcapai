import "dotenv/config";
import cors from "cors";
import express from "express";
import { apiConfig } from "./config.js";
import { createAgentRouter } from "./http/routes.js";

const app = express();

app.use(cors({ origin: apiConfig.corsOrigins }));
app.use(express.json({ limit: apiConfig.jsonLimit }));
app.use("/api", createAgentRouter());

app.get("/", (_req, res) => {
  res.json({ service: "pcapAI JS agent API", docs: "/api/health" });
});

app.listen(apiConfig.port, apiConfig.host, () => {
  console.log(`pcapAI API listening on http://${apiConfig.host}:${apiConfig.port}`);
});
