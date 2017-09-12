var db  = require('./db');
var Bookshelf = require('bookshelf')(db);
Bookshelf.plugin('registry');

module.exports = Bookshelf.Model.extend({
    tableName: 'location',
    hasTimestamps: true,
    measures: function() {
        return this.hasMany(Measure);
    },
    providers: function() {
        return this.belongsToMany(Provider);
    }
});
