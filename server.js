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
var sa = require('superagent');
var db  = require('./db');
var Bookshelf = require('bookshelf')(db);
var PythonShell = require('python-shell');

Bookshelf.plugin('registry');

var Location = Bookshelf.Model.extend({
	tableName: 'location',
    hasTimestamps: true,
	measures: function() {
        return this.hasMany(Measure);
    },
	providers: function() {
		return this.belongsToMany(Provider);
	}
});

var User = Bookshelf.Model.extend({
	tableName: 'user',
	hasTimestamps: true,
    locations: function(){
		return this.hasMany(Location)
	},
});

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

var LocationProvider = Bookshelf.Model.extend({
	tableName: 'location_provider',
    hasTimestamps: false
});

app.use(bodyParser());
app.use(cors());

var tokenSecret = 'verySecret';

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
      return done(null, user.toJSON());
    });
  }
));

app.get('/api', function (req, res) {
  res.send('Hello World!')
})

app.post('/api/register', function(req, res) {
	const user = req.body;
	console.log(user);
	if(!user.captcharesponse || !user.username || !user.password1 || !user.password2 || user.password1 !== user.password2 ) {
		res.sendStatus(403);
	}

    sa.post('https://www.google.com/recaptcha/api/siteverify')
		.send({
			secret: '6LexqSAUAAAAAGP3Nw4RnKwYn_KQc7BH-jmFksjN',
			response: user.captcharesponse,
			remoteip: req.connection.remoteAddress
		})
		.end(function(err, response) {
			if(err){ console.log(err); res.sendStatus(403); }
			console.log(user);
            User.forge({
                username: user.username,
                password: user.password1,
                role: 'user',
                enabled: true
            }).save().then((user) => {
                res.send({
                    username: user.get('username'),
                    id: user.get('id'),
                });
            }, (error) => {
                console.log(error);
                res.sendStatus(403);
            })
		})

})

app.post('/api/login', function(req, res, next) {
   	passport.authenticate('local', function(err, user, info) {
	    if (err) { return next(err) }
	    if (!user) {
	      return res.status(401).json({ reason: 'User not existent' });
	    }
	    var token = jwt.encode({ userId: user.username}, tokenSecret);
	    res.status(200).json({ token : token , username: user.username, id: user.id, role: user.role });
  	})(req, res, next);
})

app.all('/api/user/*', passport.authenticate(['jwt','basic'], { session: false }), function(req, res, next) {
    if(req.user.id === parseInt(req.params.id) || req.user.role === 'admin') {
        next();
    } else{
    	res.sendStatus(401);
	}

})

app.get('/api/user/all', function(req, res){
	const user = req.user;
	if(user.role === 'admin') {
        User.fetchAll().then((users) => {
            res.send(users);
    	});
    }else{
		res.sendStatus(401, "You are not authorized to perform that action");
	}
})


app.get('/api/user/current', function(req, res) {
	res.send(req.user);
})

app.get('/api/user/current/installation',function(req,res) {
    Location.where('user_id', req.user.id).fetchAll().then((locations) => {
        res.send(locations);
    })
})

app.get('/api/user/:id', function(req, res) {
	User.where('id', req.params.id).fetch().then((user) => {
	  res.send(user);
	});
})

app.post('/api/user/:id/installation', function(req, res) {
	const user = req.user;
	const location = req.body;
	Location.forge({
		name: location.name, 
		publickey: location.publickey, 
		user_id: user.id,
		enabled: true
	}).save().then( (location) => {
		res.send(location.toJSON());
	});
})

app.get('/api/user/:id/installation', function(req, res) {
	Location.where('user_id', req.params.id).fetchAll({withRelated: ['providers']}).then((locations) => {
		res.send(locations);
	})
})

app.get('/api/user/:id/installation/:installationId', function(req,res) {
	Location.where('id', req.params.installationId).where('user_id', req.params.id).fetch({withRelated: ['providers']}).then((installation) => {
		res.send(installation);
	})
})

app.delete('/api/user/:id/installation/:installationId', function(req, res){
	Location.where('id', req.params.installationId).where('user_id', req.params.id).save({enabled: false}).then(() => res.sendStatus(200));
})

app.get('/api/user/:id/reports', function(req, res) {
    var query = Measure.where('user_id', req.params.id);
    if(req.query.installationId){
        query = query.where('location_id', req.query.installationId);
    }
    if(req.query.provider_id && req.query.provider_id > 0){
        query = query.where('provider_id', req.query.providerId);
    }
    if(req.query.startDate){
        query = query.where('timestamp', '>' , req.query.startDate);
    }
    if(req.query.endDate){
        query = query.where('timestamp', '<', req.query.endDate);
    }
    query.fetchAll().then((data) => {
        res.send(data);
    })
})

app.post('/api/user/:id/installation/:installationId/reports', function(req,res) {
	const user = req.user;
	const report = req.body;

    var options = {
        scriptPath: 'ipToas',
        args: [report.ip]
    };

    PythonShell.run('info.py', options, function (err, result) {
        if(err) res.status(500).send('Could not calculate ipToAs');

        const as = result[0].split(',')[0];
        console.log("AS found: " + as);
        Provider.where('name', as).fetch().then((provider) => {
        	console.log(provider);
			if(!provider){
				Provider.forge({
					name: as
				}).save().then((provider) => {
					createReport(res, report, provider.id, req.params.installationId, req.params.id);
				})
			} else {
                createReport(res, report, provider.id, req.params.installationId, req.params.id);
			}
		})
    });

})

function createReport(res, report, provider_id, installation_id, user_id){
    LocationProvider.where({location_id: installation_id, provider_id: provider_id}).fetch().then((relation) => {
    	if(!relation){
    		LocationProvider.forge({location_id: installation_id, provider_id: provider_id}).save();
		}
	});
	Measure.forge({
        upUsage: report.upUsage,
		downUsage: report.downUsage,
    	upQuality: report.upQuality,
    	downQuality: report.downQuality,
    	timestamp: new Date(report.timestamp * 1000),
    	location_id: installation_id,
    	provider_id: provider_id,
    	user_id: user_id
	}).save().then((measure) => res.send(measure));
}

app.listen(3001, function () {
  console.log('Example app listening on port 3001!')
})
