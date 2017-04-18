
exports.up = function(knex, Promise) {
	return Promise.all([
		knex.schema.createTable('user', function(table) {
			table.increments();
			table.string('username').unique();
			table.string('password');
			table.boolean('enabled');
			table.string('role');
		}),
		knex.schema.createTable('location', function(table) {
			table.increments()
			table.string('name');
			table.string('publickey');
			table.integer('user_id').unique().references('user.id');
		}),
		knex.schema.createTable('provider', function(table) {
			table.increments('id').primary();
			table.string('name');
		}),
		knex.schema.createTable('measure', function(table) {
			table.increments();
			table.integer('usagePercentage');
			table.integer('upUsage');
			table.integer('downUsage');
			table.integer('upQuality');
			table.integer('downQuality');
			table.timestamp('timestamp');
			table.integer('location_id').references('location.id');
			table.integer('provier_id').references('provider.id');
		})
	])
};

exports.down = function(knex, Promise) {
	return Promise.all([
    	knex.schema.dropTable('measure'),
    	knex.schema.dropTable('provider'),
    	knex.schema.dropTable('location'),
    	knex.schema.dropTable('user')
	])
};
