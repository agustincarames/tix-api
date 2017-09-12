var User = require('../models/User');
var contracts = require('../contracts');
var nodemailer = require('nodemailer');
var uuidv4 = require('uuid/v4');
var Crypto = require('crypto');
var R = require('ramda');

var updateUser = (req, res, body) => {
    return User.where('id', req.params.id).fetch().then((user) => {
        if (hashPassword(body.oldPassword, user.get('salt')) !== user.get('password')) {
            res.code(403).json({reason: 'passwords do not match'});
            return;
        }
        if(body.newPassword) {
            var salt = generateSalt();
            var hashedPassword = hashPassword(body.newPassword, salt);
            user.save({password: hashedPassword, salt: salt}, {
                method: 'update',
                patch: true
            }).then((user) => res.send(contracts.userContract(user)));
        } else if(body.username){
            user.save({username: body.username}, {method: 'update', patch: true}).then((user) => res.send(userContract(user)));
        }
    });
};

var createUser = (res, user) => {
    var salt = generateSalt();
    var hashedPassword = hashPassword(user.password1, salt);
    User.forge({
        username: user.username,
        password: hashedPassword,
        role: 'user',
        salt: salt,
        enabled: true
    }).save().then((user) => {
        res.send({
            username: user.get('username'),
            id: user.get('id'),
        });
    }, (error) => {
        res.status(403).json({reason: 'Error while creating user'});
    })
}

var getUserById = (req, res) => {
    User.where('id', req.params.id).fetch().then((user) => {
        res.send(userContract(user));
    });
};

var getAllUsers = (req, res) => {
    User.fetchAll().then((users) => {
        res.send(R.map(contracts.userContract, users));
    });
}

var getUserByUsernameAndPassword = (req, res) => {
    User.where('username', req.body.email).fetch().then(user => {
        if(user.get('recoveryToken') === req.body.code){
            var salt = generateSalt();
            var hashedPassword = hashPassword(req.body.password, salt);
            user.save({password: hashedPassword, salt: salt, recoveryToken: null},{method: 'update', patch: true}).then((answer) => res.status(200).json({reason: 'Password updated successfully'}));
        } else{
            res.send(403).json({reason: 'Incorrect code'});
        }

    });
};

var sendUserRecoveryEmail = (req, res) => {
    User.where('username', req.body.email).fetch().then(user => {
        var recoveryToken = uuidv4();
        user.save({recoveryToken: recoveryToken},{method: 'update', patch: true}).then((answer) => res.status(200).json({reason: 'Recovery code sent successfully'}));
        transporter.sendMail(createEmail(user.username, recoveryToken), (error, info) => {
            if (error) {
                return console.log(error);
            }
            console.log('Message %s sent: %s', info.messageId, info.response);
        });
    });
};

function createEmail(to, code) {
    return {
        from: '"TiX Service" <info@tix.innova-red.net>',
        to: to,
        subject: 'Recuperar Clave',
        text: 'Para recuperar su contraseña siga el siguiente link: http://tix.innova-red.net/recover?code=' + code + '&email=' +  to, // plain text body
        html: `<html>
                <body>
                    Para recuperar su contraseña siga el siguiente link <a href=\"http://tix.innova-red.net/recover?code=${code}&email=${to}\"
                    O ingrese a http://tix.innova-red.net/recover e ingrese el codigo ${code}
                </body>
               </html>`
    };
}

// create reusable transporter object using the default SMTP transport
let transporter = nodemailer.createTransport({
    host: 'localhost',
    port: 465,
    secure: true, // secure:true for port 465, secure:false for port 587
});

function generateSalt() {
    var salt = Crypto.randomBytes(126);
    return salt.toString('base64');
};

var hashPassword = (password, salt) => {
    console.log(password);
    console.log(salt);
    var hmac =  Crypto.createHmac('sha512', salt);
    hmac.setEncoding("base64");
    hmac.write(password);
    hmac.end();
    return hmac.read();
};

module.exports = {
    sendUserRecoveryEmail: sendUserRecoveryEmail,
    getUserByUsernameAndPassword: getUserByUsernameAndPassword,
    getAllUsers: getAllUsers,
    getUserById: getUserById,
    createUser: createUser,
    updateUser: updateUser,
    hashPassword: hashPassword,
};