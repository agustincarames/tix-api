var Provider = require('../models/Provider');
var contracts = require('../contracts');


var getProvider = (providerId) => {
    return Provider.where('id', providerId).fetchAll();
};

var getProviders = (req, res) => {
    return Provider.fetchAll();
};

module.exports = {
    getProvider: getProvider,
    getProviders: getProviders,
};