var db  = require('./db');
var Bookshelf = require('bookshelf')(db);
var Location = require('./Location');
Bookshelf.plugin('registry');

var User = Bookshelf.Model.extend({
    tableName: 'user',
    hasTimestamps: true,
    locations: function(){
        return this.hasMany(Location)
    },
});

module.exports = {
    User: User
};