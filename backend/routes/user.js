const express = require('express');
const zod = require('zod');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { User, Account } = require('../db');
const { JWT_SECRET } = require('../config');
const authMiddleware = require('../middleware');

const userRouter = express.Router();

const updateZod = zod.object({
    password: zod.string().min(6),
    firstName: zod.string().max(50).trim(),
    lastName: zod.string().max(50).trim(),
});

userRouter.put('/', authMiddleware, async (req, res) => {
    const { success, error } = updateZod.safeParse(req.body);

    if (!success) {
        return res.status(400).send({
            message: "Incorrect inputs",
            error: error.errors,
        });
    }

    try {
        const existingUser = await User.findById(req.userId);

        if (!existingUser) {
            return res.status(404).send({
                message: "User is not registered",
            });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        await User.updateOne(
            { _id: req.userId },
            {
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                password: hashedPassword,
            }
        );

        return res.json({
            message: "Update successfully",
        });
    } catch (error) {
        console.error(error);
        return res.status(500).send({
            message: "Internal server error",
        });
    }
});

const signupZod = zod.object({
    userName: zod.string().email().max(30).trim().toLowerCase(),
    password: zod.string().min(6),
    firstName: zod.string().max(50).trim().min(1).max(50),
    lastName: zod.string().max(50).trim().min(1).max(50),
});

userRouter.post('/signup', async (req, res) => {
    const { success, error, data } = signupZod.safeParse(req.body);

    if (!success) {
        return res.status(400).send({
            message: "Invalid input",
            error: error.errors,
        });
    }

    function capitalizeFirstChar(str) {
        return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
    }

    const { userName, password, firstName, lastName } = data;

    const balance = Math.floor(Math.random() * 3 + 8) * 1000 * 100;

    try {
        const existingUser = await User.findOne({ userName });

        if (existingUser) {
            return res.status(400).send({
                message: "Email already taken",
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            userName,
            password: hashedPassword,
            firstName: capitalizeFirstChar(firstName),
            lastName: capitalizeFirstChar(lastName),
        });

        const userId = user._id;
        const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });

        await Account.create({
            userId,
            balance,
        });

        return res.status(201).send({
            message: "User created successfully",
            token,
        });
    } catch (error) {
        console.error(error);
        return res.status(500).send({
            message: "Internal server error",
        });
    }
});

const signinZod = zod.object({
    userName: zod.string().email().min(3).max(30).trim().toLowerCase(),
    password: zod.string().min(6),
});

userRouter.post('/signin', async (req, res) => {
    const { success, error, data } = signinZod.safeParse(req.body);

    if (!success) {
        return res.status(400).send({
            message: "Incorrect  username or password",
            error: error.errors,
        });
    }

    const { userName, password } = data;

    try {
        const user = await User.findOne({ userName });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send({
                message: "Incorrect username or password",
            });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

        return res.status(200).send({
            message: "Login successful",
            token,
        });
    } catch (error) {
        console.error(error);
            return res.status(500).send({
                message: "Internal server error",
            });
    }
});

userRouter.get('/bulk', async (req, res) => {
    const filter = req.query.filter || "";
    const regex = new RegExp(filter, "i");

    try {
        const users = await User.find({
            $or: [
                { firstName: { $regex: regex } },
                { lastName: { $regex: regex } },
            ],
        });

        if (users.length > 0) {
            return res.json({
                users: users.map(user => ({
                    userName: user.userName,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    id: user._id,
                })),
            });
        } else {
            return res.status(404).send({
                message: "No users found",
            });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).send({
            message: "Internal server error",
        });
    }
});

module.exports = userRouter;
