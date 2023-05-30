import express from "express";
import passport from "passport";
import jwt from "jsonwebtoken";
import {
  processRegisterForm,
  closeSession,
  showLoginForm,
  showRegisterForm,
  processLoginForm,
  processPasswordResetRequest,
  showPasswordResetExpiredPage,
  showPasswordResetForm,
  processPasswordReset,
  showPasswordResetRequestForm,changeUserRoleController
} from "../controllers/controllerDb/userController.js";
import { admin } from "../middlewares/index.js";
import { config } from "../config/env.config.js";

const router = express.Router();
const jwtSecret = config.jwtSecret;

//rutas de Login
router.get("/login", showLoginForm);
router.post("/login", admin, processLoginForm);
router.get("/logout", closeSession);
router.get("/register", showRegisterForm);
router.post("/register", processRegisterForm);

// Rutas de restablecimiento de contraseña
router.get('/password/reset-request', showPasswordResetRequestForm);
router.post('/password/reset-request', processPasswordResetRequest);
router.get('/password/expired', showPasswordResetExpiredPage);
router.get('/password/reset/:token', showPasswordResetForm);
router.post('/password/reset/:token', processPasswordReset);

// Ruta para cambiar el rol de un usuario a "premium"
router.put("/users/premium/:uid", changeUserRoleController);

// Otras rutas
router.get(
  "/current",
  passport.authenticate("current", { session: false }),
  (req, res) => {
    res.json(req.user);
  }
);
// Ruta de GitHub
router.get("/github", passport.authenticate("github"));
router.get(
  "/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  (req, res) => {
    const token = jwt.sign(
      {
        Id: req.user._id,
        first_name: req.user.first_name,
        role: req.user.role,
      },
      jwtSecret
    );
    res.cookie("token", token);
    res.redirect("/api/products");
  }
);

export default router;