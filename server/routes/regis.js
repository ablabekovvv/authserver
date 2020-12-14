const Router = require("express");
const User = require("../models/User")
const bcrypt = require("bcryptjs")
const {check, validationResult} = require("express-validator")
const config = require("config")
const jwt = require("jsonwebtoken")
const router = new Router()


router.post('/registration',
    [
        check('email', "Неправильный email").isEmail(),
        check('password', 'Пароль должен быть длиннее 5 символов и меньше 12').isLength({min:5, max:12})
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({message: "Неправильный запрос", errors})
    }
        const {email, password} = req.body
        const candidate = User.findOne({email})
        if(candidate) {
            return res.status(400).json({message: `Пользователь с данным email ${email} уже используется`})
    }
    const hashPassword = await bcrypt.hash(password, 8)
    const user = new User({email, password: hashPassword})
    await user.save()
    return res.json({message: "Аккаунт успешно создан!"})
} catch (e) {
        console.log(e)
        res.send({message: "Ошибка сервера"})
    }
})


router.post('/login',
    async (req, res) => {
    try {
        const {email, password} = req.body
        const user = await User.findOne({email})
        if (!user) {
            return res.status(404).json({message: "Пользователь не найден"})
        }
        const isPassValid = bcrypt.compareSync(password, user.password)
        if(!isPassValid) {
            return res.status(400).json({message: "Неправильный пароль"})
        }
        const token = jwt.sign({id: user.id}, config.get("secretKey"), {expiresIn: "1h"})
        return res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                diskSpace: user.diskSpace
                usedSpace: user.usedSpace
                avatar: user.avatar
            }
        })
    } catch (e) {
        console.log(e)
        res.send({message: "Ошибка сервера"})
    }
})


module.exports = router