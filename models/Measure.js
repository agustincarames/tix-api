var db  = require('./db-stats');
var Bookshelf = require('bookshelf')(db);
Bookshelf.plugin('registry');

module.exports = Bookshelf.Model.extend({
    tableName: 'measure',
    hasTimestamps: true
});
