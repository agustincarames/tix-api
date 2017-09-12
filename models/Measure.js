var db  = require('./db');
var Bookshelf = require('bookshelf')(db);
var Location = require('./Location');
var Provider = require('./Provider');
Bookshelf.plugin('registry');

var Measure = Bookshelf.Model.extend({
    tableName: 'measure',
    hasTimestamps: true,
    provider: function() {
        return this.belongsTo(Provider, 'provider_id');
    },
    location: function() {
        return this.belongsTo(Location, 'location_id');
    }
});

module.exports = {
    Measure: Measure
};
