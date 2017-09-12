var Provider = require('../models/Provider');

var getProvider = (providerId) => {
    return Provider.where('id', providerId).fetchAll();
};

var getProviders = () => {
    return Provider.fetchAll();
};

module.exports = {
    getProvider: getProvider,
    getProviders: getProviders,
};