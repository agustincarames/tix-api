var Location = require('../models/Location');
var contracts = require('../contracts');
var R = require('ramda');

var deleteInstallation = (installationId, userId) => {
    return Location.where('id', installationId).where('user_id', userId).where('enabled', true).fetch()
        .then((installation) => installation.save({enabled: false},{method: 'update', patch: true}));
};

var updateInstallation = (installationId, userId, name) => {
    return Location.where('id', installationId).where('user_id', userId).where('enabled', true).fetch()
        .then(installation => installation.save({name: name},{method: 'update', patch: true}));
};

var getInstallation = (installationId, userId) => {
    return Location.where('id', installationId).where('user_id', userId).where('enabled', true).fetch({withRelated: ['providers']})
};

var getInstallations = (userId) => {
    return Location.where('user_id', userId).where('enabled', true).fetchAll({withRelated: ['providers']})
};

var getInstallationByUserId = (req, res) => {
    Location.where('user_id', req.user.id).fetchAll().then((locations) => {
        res.send(R.map(contracts.installationContract, locations));
    })
}

var createInstallation = (location, user) => {
    return Location.forge({
        name: location.name,
        publickey: location.publickey,
        user_id: user.id,
        enabled: true
    }).save();
}

module.exports = {
    deleteInstallation: deleteInstallation,
    updateInstallation: updateInstallation,
    getInstallation: getInstallation,
    getInstallations: getInstallations,
    createInstallation: createInstallation,
    getInstallationByUserId: getInstallationByUserId,
};