var Sequelize = require('Sequelize');
var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
var cors = require('cors');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var jwt = require('jwt-simple');
var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;

var db  = require('./db');
var Bookshelf = require('bookshelf')(db);

var Location = Bookshelf.Model.extend({
	tableName: 'location',
	user: function() {
		return this.belongsTo(User);
	},
	measures: function() {
		return this.hasMany(Measure);
	}
});

var User = Bookshelf.Model.extend({
  tableName: 'user',
  locations: function(){
  		return this.hasMany(Location)
  },
});

var Provider = Bookshelf.Model.extend({
	tableName: 'provider',
	measures: function() {
		return this.hasMany(Measure);
	}
});

var Measure = Bookshelf.Model.extend({
	tableName: 'measure',
	provider: function() {
		return this.belongsTo(Provider);
	},
	location: function() {
		return this.belongsTo(Location);
	}
});

app.use(bodyParser());
app.use(cors());

var tokenSecret = 'verySecr' +
	'et';

passport.use(new LocalStrategy(
  	function(username, password, done) {
    	User.where('username', username).fetch().then((user) => {
      		if (!user) {
      			return done(null, false, { reason: 'Incorrect username.' });
      		}
      		if (password != user.get('password')) {
        		return done(null, false, { reason: 'Incorrect password.' });
      		}
      		return done(null, user.toJSON());
    	});
  	}
));

passport.use(new JwtStrategy({ secretOrKey: tokenSecret, jwtFromRequest: ExtractJwt.fromAuthHeader() }, 
	function(jwt_payload, done) {
	    User.where('username', jwt_payload.userId).fetch().then((user) => {
	        if (user) {
	            done(null, user.toJSON());
	        } else {
	            done(null, false);
	        }
	    });
	}
));

passport.use(new BasicStrategy(
  function(userid, password, done) {
    User.where('username', userid).fetch().then((user) => {
      if (!user) { return done(null, false); }
      if (user.get('password') !== password) { return done(null, false); }
      return done(null, user);
    });
  }
));

app.get('/api', function (req, res) {
  res.send('Hello World!')
})

app.post('/api/register', function(req, res) {
	const user = req.body;
	User.forge({
		username: user.username,
		password: user.password,
		role: 'user',
		enabled: true
	}).save().then((user) => {
		res.send({
			username: user.get('username'), 
			id: user.get('id'),
		});
	}, (err) => {
		console.log(err);
		res.sendStatus(403);
	})
})

app.post('/api/login', function(req, res, next) {
   	passport.authenticate('local', function(err, user, info) {
	    if (err) { return next(err) }
	    if (!user) {
	      return res.status(401).json({ reason: 'User not existent' });
	    }
	    var token = jwt.encode({ userId: user.username}, tokenSecret);
	    res.status(200).json({ token : token , username: user.username});
  	})(req, res, next);
})

app.all('/api/user/*', passport.authenticate(['jwt','basic'], { session: false }), function(req, res, next) {
	next();
})

app.get('/api/user/current', function(req, res) {
	res.send(req.user);
})


app.get('/api/user/:id', function(req, res) {
	const user = req.user;
	if(user.id === parseInt(req.params.id) || user.attributes.role === 'admin'){
		User.where('id', req.params.id).fetch().then((user) => {
	      res.send(user);
	    });
	} else {
        res.sendStatus(403);
	}
})

app.post('/api/user/:id/installation', function(req, res) {
	const user = req.user;
	const location = req.body;
	Location.forge({
		name: location.name, 
		publickey: location.publickey, 
		user_id: user.id
	}).save().then( (location) => {
		res.send(location.toJSON());
	});
})

app.get('/api/user/:id/installation', function(req, res) {
    if(req.user.id === parseInt(req.params.id) || req.user.attributes.role === 'admin') {
        Location.where('user_id', req.params.id).fetchAll().then((locations) => {
            res.send(locations);
    	})
    } else {
    	res.sendStatus(403);
	}
})

app.get('/api/user/:id/installation/:installationId', function(req,res) {
	Location.where('id', req.params.installationId).fetch().then((installation) => {
		res.send(installation);
	})
})

app.get('/api/user/:id/installation/:installationId/reports', function(req, res) {
	Report.where('location_id', req.params.installationId).fetchAll().then((data) => {
		res.send(data);
	})
})

app.post('/api/user/:id/installation/:installationId/reports', function(req,res) {
	const user = req.user;
	const report = req.body;
	Report.forge({
		usagePercentage: report.usagePercentage,
		upUsage: report.upUsage,
		downUsage: report.downUsage,
		upQuality: report.upQuality,
		downQuality: report.downQuality,
		timestamp: report.timestamp,
		location_id: req.params.installationId,
		provider_id: report.provider_id
	}).save().then((report) => {
		res.send(report.toJSON());
	})
})

app.listen(3001, function () {
  console.log('Example app listening on port 3001!')
})
