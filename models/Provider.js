var db  = require('./db');
var Bookshelf = require('bookshelf')(db);
var Location = require('./Location');
var Measure = require('./Measure');
Bookshelf.plugin('registry');

var Provider = Bookshelf.Model.extend({
    tableName: 'provider',
    hasTimestamps: true,
    measures: function() {
        return this.hasMany(Measure);
    },
    locations: function() {
        return this.belongsToMany(Location);
    }
});

module.exports = {
    Provider: Provider
};
