"use strict";

const { Sequelize } = require("sequelize");
const { sequelize, User } = require("../models");
const jwt = require("jsonwebtoken");

const bcrypt = require("bcrypt");
const saltRounds = 10;
const myPlaintextPassword = "s0//P4$$w0rD";
const someOtherPlaintextPassword = "not_bacon";

require("dotenv").config();

module.exports = class VerifyAccess {
    constructor() {}

    async generateAccessToken(user) {
        return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: "3600s",
        });
    }

    async generateRefreshToken(user) {
        return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
            expiresIn: "7200s",
        });
    }

    async authenticateAdminToken(req, res, next) {
        if (!req.headers.auth || !req.headers.auth.includes(" ")) {
            return res.status(401).send("Demande non autorisée");
        }
        let token = req.headers.auth.split(" ")[1];
        if (token === null) {
            return res.status(401).send("Demande non autorisée");
        }
        let user = jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET,
            (err, user) => {
                if (err) {
                    return (user = err.message);
                } else {
                    return user;
                }
            }
        );
        if (typeof user === "string") {
            return res.status(401).send(user);
        }

        if (user.role.name !== "admin") return res.sendStatus(401);

        req.user = user;
        next();
    }

    async authenticateRefreshToken(req, res, next) {
        if (!req.params.refreshToken) {
            return res.status(401).send("Demande non autorisée");
        }
        let token = req.params.refreshToken;
        if (token === null) {
            return res.status(401).send("Demande non autorisée");
        }
        let user = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.status(401).send(err.message)
            } else {
                return user
            }
        });
        if (!user) {
            return res.status(401).send("Demande non autorisée");
        }


        req.user = user;
        req.refreshToken = token;
        next();
    }

    async authenticateValidateToken(req, res, next) {
        if (!req.params.accessToken) {
            return res.status(401).send("Demande non autorisée");
        }
        let token = req.params.accessToken;
        if (token === null) {
            return res.status(401).send("Demande non autorisée");
        }
        let user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.status(401).send(err.message)
            } else {
                return user
            }
        });
        if (!user) {
            return res.status(401).send("Demande non autorisée");
        }


        req.user = user;
        req.refreshToken = token;
        next();
    }
    async authenticateUserToken(req, res, next) {
        if (!req.headers.auth || !req.headers.auth.includes(" ")) {
            return res.status(401).send("Demande non autorisée");
        }
        let token = req.headers.auth.split(" ")[1];
        if (token === null) {
            return res.status(401).send("Demande non autorisée");
        }
        let user = jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET,
            (err, user) => {
                if (err) {
                    return (user = err.message);
                } else {
                    return user;
                }
            }
        );
        if (typeof user === "string") {
            return res.status(401).send(user);
        }

        req.user = user;
        next();
    }

    async hashPassword(pwd) {
        return bcrypt.hashSync(pwd, 10);
    }

    async comparePassword(enteredPassword, originalPassword) {
        return await bcrypt.compare(enteredPassword, originalPassword);
    }
};