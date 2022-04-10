"use strict";

const express = require("express");
const { Sequelize } = require("sequelize");
const { sequelize, User, Role } = require("../models");
const jwt = require("jsonwebtoken");
var VerifyAccess = require("../services/verifyAccess.js");
var EmailController = require("../services/emailServices");
const nodemailer = require("nodemailer");
const jwt_decode = require('jwt-decode');

const verifyAccess = new VerifyAccess();
const emailController = new EmailController();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const router = express.Router();

const bcrypt = require("bcrypt");
const { json } = require("body-parser");
//const { ne } = require('sequelize/dist/lib/operators');
const saltRounds = 10;
const myPlaintextPassword = "s0//P4$$w0rD";
const someOtherPlaintextPassword = "not_bacon";
var randtoken = require("rand-token");

require("connect-flash");
var ExpressBrute = require("express-brute"),
    MemcachedStore = require("express-brute-memcached"),
    moment = require("moment"),
    store;

//if (config.environment == "development") {
store = new ExpressBrute.MemoryStore(); // stores state locally, don't use this in production
/*} else {
  // stores state with memcached
  store = new MemcachedStore(["127.0.0.1"], {
    prefix: "NoConflicts",
  });
}*/

var failCallback = function(req, res, next, nextValidRequestDate) {
    res.status(401).send({
        message: "You've made too many failed attempts in a short period of time, please try again " +
            moment(nextValidRequestDate).fromNow(),
    }); // brute force protection triggered, send them back to the login page
};
var handleStoreError = function(error) {
    log.error(error); // log this error so we can figure out what went wrong
    // cause node to exit, hopefully restarting the process fixes the problem
    throw {
        message: error.message,
        parent: error.parent,
    };
};
// Start slowing requests after 3 failed attempts to do something for the same user
var userBruteforce = new ExpressBrute(store, {
    freeRetries: 3,
    minWait: 5 * 60 * 1000, // 5 minutes
    maxWait: 60 * 60 * 1000, // 1 hour,
    failCallback: failCallback,
    handleStoreError: handleStoreError,
});
// No more than 1000 login attempts per day per IP
var globalBruteforce = new ExpressBrute(store, {
    freeRetries: 1000,
    attachResetToRequest: false,
    refreshTimeoutOnRequest: false,
    minWait: 25 * 60 * 60 * 1000, // 1 day 1 hour (should never reach this wait time)
    maxWait: 25 * 60 * 60 * 1000, // 1 day 1 hour (should never reach this wait time)
    lifetime: 24 * 60 * 60, // 1 day (seconds not milliseconds)
    failCallback: failCallback,
    handleStoreError: handleStoreError,
});

require("dotenv").config();

/**
 * @swagger
 * /register:
 *   post:
 *     summary:  JSONPlaceholder.
 *     tags: [Auth]
 *     description: prototyping or testing an API.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstname:
 *                 type: string
 *                 description: .
 *                 example: John
 *               lastname:
 *                 type: string
 *                 description: .
 *                 example: Doe
 *               email:
 *                 type: string
 *                 description: .
 *                 example: john.doe@gmail.com
 *               password:
 *                 type: string
 *                 description: .
 *                 example: John1234
 *               address:
 *                 type: string
 *                 description: .
 *                 example: 123 rue de france
 *               postalCode:
 *                 type: string
 *                 description: .
 *                 example: 13090
 *               city:
 *                 type: string
 *                 description: .
 *                 example: Aix-en-provence
 *               country:
 *                 type: string
 *                 description: .
 *                 example: France
 *     responses:
 *       200:
 *         description: .
 */
router.post("/register", async(req, res) => {
    try {
        var userToFind = await User.findOne({ where: { email: req.body.email } });

        if (userToFind) {
            console.error("ERROR: Un compte avec cet email existe déjà");
            return res
                .status(400)
                .json({ error: "Un compte avec cet email existe déjà" });
        }

        var hashPWD = bcrypt.hashSync(req.body.password, 10);
        var randPseudo = req.body.firstname + ~~(Math.random() * (9 - 1 + 1) + 1);
        var user = {
            pseudo: randPseudo,
            firstname: req.body.firstname,
            lastname: req.body.lastname,
            email: req.body.email,
            password: hashPWD,
            address: req.body.address,
            postalCode: req.body.postalCode,
            city: req.body.city,
            country: req.body.country,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date(),
            roleId: 1,
        };
        let user2 = await User.create(user);
        let role = await Role.findOne({
            where: { id: user.roleId },
        });
        user.id = user2.id;
        user.role = {};
        user.role.id = role.id;
        user.role.name = role.name;

        let accessToken = (await verifyAccess.generateAccessToken(user)).toString();
        let refreshToken = (
            await verifyAccess.generateRefreshToken(user)
        ).toString();

        emailController.register(req.body.email);

        res.send({
            accessToken,
            refreshToken,
        });
    } catch (err) {
        console.log(err);
        return res.status(500).json(err);
    }
}); // Fin de la méthode register

/**
 * @swagger
 * /token:
 *   post:
 *     summary: JSONPlaceholder.
 *     tags: [Access token]
 *     description: prototyping or testing an API.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: .
 *                 example: admin@example.com
 *               password:
 *                 type: string
 *                 description: .
 *                 example: admin1234
 *     responses:
 *       200:
 *         description: .
 */

router.post(
    "/token",
    globalBruteforce.prevent,
    userBruteforce.getMiddleware({
        key: function(req, res, next) {
            // prevent too many attempts for the same username
            next(req.body.username);
        },
    }),
    async(req, res) => {
        try {
            let email = req.body.email.trim();
            const userToFind = await User.findOne({
                where: { email: email },
                include: [{ model: Role, as: "role" }],
            });
            if (!userToFind) {
                console.error("invalid credentials");
                return res.status(400).json({ error: "invalid credentials" });
            }
            // TODO: fetch le user depuis la db basé sur l'email passé en paramètre
            let enteredPassword = req.body.password;
            let originalPassword = userToFind.password;
            const correctPassword = await verifyAccess.comparePassword(
                enteredPassword,
                originalPassword
            );

            if (!userToFind) {
                res
                    .status(401)
                    .send({ message: "Aucun utilisateur trouvé pour cette adresse email" });
                return;
            }

            emailController.login(req.body.email);

            if (!correctPassword) {
                res
                    .status(401)
                    .send({ message: "Mot de passe incorrect pour cet utilisateur" });
                return;
            }

            let newUser = {
                id: userToFind.id,
                pseudo: userToFind.pseudo,
                firstname: userToFind.firstname,
                lastname: userToFind.lastname,
                email: userToFind.email,
                address: userToFind.address,
                postalCode: userToFind.postalCode,
                city: userToFind.city,
                country: userToFind.country,
                role: {
                    id: userToFind.role.id,
                    name: userToFind.role.name,
                },
            };

            let newToken = await verifyAccess.generateAccessToken(newUser);
            let newRefreshToken = await verifyAccess.generateRefreshToken(newUser)
            let accessTokenDecoded = jwt_decode(newToken);
            let refreshTokenDecoded = jwt_decode(newRefreshToken)
            let accessToken = (newToken).toString();
            let accessTokenExpiresAt = new Date(accessTokenDecoded.exp * 1000)
            let refreshToken = (newRefreshToken).toString();
            let refreshTokenExpiresAt = new Date(refreshTokenDecoded.exp * 1000)
            console.log(newToken)
            res.send({
                accessToken,
                accessTokenExpiresAt: accessTokenExpiresAt.toLocaleString(),
                refreshToken,
                refreshTokenExpiresAt: refreshTokenExpiresAt.toLocaleString()
            });
        } catch (err) {
            console.log(err);
            return res.status(500).json(err);
        }
    }
); // Fin de la méthode login

/**
 * @swagger
 * /refresh-token/{refreshToken}/token:
 *   post:
 *     summary:  JSONPlaceholder.
 *     tags: [Refresh token]
 *     parameters:
 *      - name: refreshToken
 *        in: path
 *     description: refreshToken Token à consommer
 *     responses:
 *       200:
 *         description: .
 */

router.post(
    "/refresh-token/:refreshToken/token",
    verifyAccess.authenticateRefreshToken,
    async(req, res) => {
        try {
            console.log(req.params.refreshToken)

            let user = req.user;
            delete user.iat;
            delete user.exp;
            let newToken = await verifyAccess.generateAccessToken(user);
            let accessTokenDecoded = jwt_decode(newToken);
            let refreshTokenDecoded = jwt_decode(req.refreshToken)
            let accessTokenExpiresAt = new Date(accessTokenDecoded.exp * 1000);
            let refreshTokenExpirationDate = new Date(refreshTokenDecoded.exp * 1000)
            let accessToken = (
                newToken
            ).toString();
            res.send({
                accessToken: accessToken,
                accessTokenExpiresAt: accessTokenExpiresAt.toLocaleString(),
                refreshToken: req.refreshToken,
                refreshTokenExpiresAt: refreshTokenExpirationDate.toLocaleString()
            });
        } catch (err) {
            console.log(err);
            return res.status(500).json(err);
        }
    }
);


/**
 * @swagger
 * /validate/{accessToken}:
 *   get:
 *     summary:  JSONPlaceholder.
 *     tags: [Access token]
 *     parameters:
 *      - name: accessToken
 *        in: path
 *     description: refreshToken Token à consommer
 *     responses:
 *       200:
 *         description: .
 */

router.get(
    "/validate/:accessToken",
    verifyAccess.authenticateValidateToken,
    async(req, res) => {
        try {

            let accessTokenDecoded = jwt_decode(req.params.accessToken);
            let accessTokenExpiresAt = new Date(accessTokenDecoded.exp * 1000);
            let accessToken = (
                req.params.accessToken
            ).toString();
            res.send({
                accessToken: accessToken,
                accessTokenExpiresAt: accessTokenExpiresAt.toLocaleString()
            });
        } catch (err) {
            console.log(err);
            return res.status(500).json(err);
        }
    }
);

/**
 * @swagger
 * /reset-password-email:
 *   post:
 *     summary: JSONPlaceholder.
 *     tags: [Auth]
 *     description: prototyping or testing an API.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: .
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: .
 */

router.post("/reset-password-email", async(req, res) => {
    try {
        var email = req.body.email;

        //console.log(sendEmail(email, fullUrl));

        var userToFind = await User.findOne({ where: { email: req.body.email } });

        console.log(userToFind);

        if (userToFind.email) {
            var token = randtoken.generate(20);

            let sent = emailController.resetEmailPassword(req.body.email, token);

            if (sent != "0") {
                userToFind.resetPasswordToken = token.toString();
                userToFind.save();
            } else {
                console.error("Something goes to wrong. Please try again");
                return res
                    .status(500)
                    .json({ error: "Something goes to wrong. Please try again" });
            }
        } else {
            console.error("invalid credentials");
            return res.status(400).json({ error: "invalid credentials" });
        }

        res.send({
            token,
        });
        //return res.status(200).send({ message: 'Email envoyé avec succès'})
    } catch (err) {
        console.log(err);
        return res.status(500).json(err);
    }
});

/**
 * @swagger
 * /update-password:
 *   post:
 *     summary: JSONPlaceholder.
 *     tags: [Auth]
 *     description: prototyping or testing an API.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 description: .
 *                 example:
 *               password:
 *                 type: string
 *                 description: .
 *                 example: user
 *     responses:
 *       200:
 *         description: .
 */
router.post("/update-password", async(req, res) => {
    try {
        var token = req.body.token;
        var password = req.body.password;

        var userToFind = await User.findOne({
            where: { resetPasswordToken: token },
        });

        if (userToFind) {
            var saltRounds = 10;

            // var hash = bcrypt.hash(password, saltRounds);

            bcrypt.genSalt(saltRounds, function(err, salt) {
                bcrypt.hash(password, salt, function(err, hash) {
                    userToFind.password = hash;
                    userToFind.resetPasswordToken = null;
                    userToFind.save();
                });
            });
        } else {
            console.error("invalid credentials");
            return res.status(400).json({ error: "invalid credentials" });
        }

        res.status(200).json({ message: "mot de passe modifié avec succès" });
    } catch (err) {
        console.log(err);
        return res.status(500).json(err);
    }
});

module.exports = router;