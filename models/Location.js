var db  = require('./db');
var Bookshelf = require('bookshelf')(db);
var Provider = require('./Provider');
Bookshelf.plugin('registry');

module.exports = Bookshelf.Model.extend({
    tableName: 'location',
    hasTimestamps: true,
    providers: function() {
        return this.belongsToMany(Provider);
    }
});
