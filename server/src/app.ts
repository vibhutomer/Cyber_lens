import express from "express";
import cors from "cors";
import resolveOwner from "./utils/resolveOwner";
import lookupRouter from "./routes/lookup";

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(resolveOwner);

// Simple health route
app.get("/", (_req, res) => res.json({ status: "ok" }));

app.use("/lookup", lookupRouter);

export default app;
