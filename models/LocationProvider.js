var db  = require('./db');
var Bookshelf = require('bookshelf')(db);
Bookshelf.plugin('registry');

var LocationProvider = Bookshelf.Model.extend({
    tableName: 'location_provider',
    hasTimestamps: false
});

module.exports = {
    LocationProvider: LocationProvider
};