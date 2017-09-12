var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
var cors = require('cors');
var LocalStrategy = require('passport-local').Strategy;
var jwt = require('jwt-simple');
var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var sa = require('superagent');
var reportService = require('./services/reportService');
var providerService = require('./services/providerService');
var locationService = require('./services/locationService');
var userService = require('./services/userService');
var User = require('./models/User');
var json2csv = require('json2csv');
var contracts = require('./contracts');

app.use(bodyParser.json());
app.use(cors());

var tokenSecret = 'verySecret';

passport.use(new LocalStrategy(
  	function(username, password, done) {
    	User.where('username', username).fetch().then((user) => {
      		if (!user) {
      			return done(null, false, { reason: 'Incorrect username.' });
      		}
      		if (user.get('password') !== userService.hashPassword(password, user.get('salt'))) {
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
      if (userService.hashPassword(password, user.get('salt')) !== user.get('password')) { return done(null, false); }
      return done(null, user.toJSON());
    });
  }
));

app.get('/api', function (req, res) {
  res.send('Hello World!')
})

app.post('/api/register', function(req, res) {
    const user = req.body;
    if(!user.captcharesponse || !user.username || !user.password1 || !user.password2 || user.password1 !== user.password2 ) {
        res.status(400).json({reason: 'Incomplete parameters'});
    }
	sa.post('https://www.google.com/recaptcha/api/siteverify')
		.send({
			secret: '6LexqSAUAAAAAGP3Nw4RnKwYn_KQc7BH-jmFksjN',
			response: user.captcharesponse,
			remoteip: req.connection.remoteAddress
		})
		.end(function(err, response) {
			if(err){ console.log(err); res.status(403).json({reason: 'Error while processing Captcha'}); }
            userService.createUser(res, user)

		})
})

app.post('/api/login', function(req, res, next) {
   	passport.authenticate('local', function(err, user, info) {
	    if (err) { return next(err) }
	    if (!user) {
	      return res.status(401).json({ reason: 'User/Password incorrect' });
	    }
	    var token = jwt.encode({ userId: user.username}, tokenSecret);
	    res.status(200).json({ token : token , username: user.username, id: user.id, role: user.role });
  	})(req, res, next);
})

app.post('/api/recover', function(req, res) {
    if(!req.body.email) { res.status(400).json({ reason: 'Incomplete parameters'})};
    userService.sendUserRecoveryEmail(req, res);
})

app.post('/api/recover/code', function(req, res) {
    if(!req.body.email || !req.body.code || !req.body.password) { res.status(400).json({ reason: 'Incomplete parameters'})};
    userService.getUserByUsernameAndPassword(req, res);
})

app.all('/api/user/*', passport.authenticate(['jwt','basic'], { session: false }), function(req, res, next) {
        next();
})

app.all('/api/admin/*', passport.authenticate(['jwt','basic'], { session: false }), function(req, res, next) {
	const user = req.user;
	if(user.role !== 'admin'){
		res.status(401).json({reason: 'You are not authorized to perform that action'})
	} else{
        next();
	}
})

app.get('/api/user/all', function(req, res){
	const user = req.user;
	if(user.role === 'admin') {
        userService.getAllUsers(req, res);
    }else{
		res.status(401).json({reason: "You are not authorized to perform that action"});
	}
})


app.get('/api/user/current', function(req, res) {
	res.send(req.user);
})

app.get('/api/user/current/installation',function(req,res) {
    locationService.getInstallationByUserId(req, res);
})

app.get('/api/user/:id', function(req, res) {
    if(req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        res.status(401).json({reason: 'The user cannot perform that operation'});
        return;
    }
	userService.getUserById(req, res);
})

app.put('/api/user/:id', function(req, res) {
    if(req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        res.status(401).json({reason: 'The user cannot perform that operation'});
        return;
    }
	var body = req.body;
    userService.updateUser(req, res, body);
})

app.post('/api/user/:id/installation', function(req, res) {
    if(req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        res.status(401).json({reason: 'The user cannot perform that operation'});
        return;
    }
	const user = req.user;
	const location = req.body;
    locationService.createInstallation(location, user).then( (location) => {
        res.send(contracts.installationContract(location));
    });;
})

app.get('/api/user/:id/installation', function(req, res) {
    if(req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        res.status(401).json({reason: 'The user cannot perform that operation'});
        return;
    }
    const userId = req.params.id;
	locationService.getInstallations(userId).then((locations) => { res.send(locations.map((location) => contracts.installationContract(location))); });;
})

app.get('/api/user/:id/installation/:installationId', function(req,res) {
    if(req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        res.status(401).json({reason: 'The user cannot perform that operation'});
        return;
    }
    const userId = req.params.id;
    const installationId = req.params.installationId;
	locationService.getInstallation(installationId, userId).then((installation) => {
	    if(installation){
            res.send(installationContract(installation));
        } else {
	        res.status(404).send("Not Found");
        }
	});
})

app.put('/api/user/:id/installation/:installationId', function(req, res) {
    if(req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        res.status(401).json({reason: 'The user cannot perform that operation'});
        return;
    }
    const name = req.body.name;
    const userId = req.params.id;
    const installationId = req.params.installationId;
    locationService.updateInstallation(installationId, userId, name).then(installation => res.send(contracts.installationContract(installation)));
})

app.delete('/api/user/:id/installation/:installationId', function(req, res){
    if(req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        res.status(401).json({reason: 'The user cannot perform that operation'});
        return;
    }
    const userId = req.params.id;
    const installationId = req.params.installationId;
    locationService.deleteInstallation(installationId, userId).then(installation => res.send(contracts.installationContract(installation)));;
})

app.get('/api/user/:id/provider', function(req, res){
	providerService.getProviders().then((providers) => res.send(providers.map(provider => contracts.providerContract(provider))));;
})

app.get('/api/user/:id/provider/:providerId', function(req, res){
    const {
        providerId
    } = req.params;
    providerService.getProvider(providerId).then((providers) => res.send(providers.map(provider => contracts.providerContract(provider))));;
})

app.get('/api/user/:id/reports', function(req, res) {
    if(req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        res.status(401).json({reason: 'The user cannot perform that operation'});
        return;
    }
    const {
        startDate,
        endDate,
        providerId,
        installationId,
    } = req.query;
    const userId = req.params.id;
    reportService.getReport(userId, installationId, providerId, startDate, endDate).then((reports) => {
        res.send(reports.map((report) => contracts.measureContract(report)));
    });;
})

app.post('/api/user/:id/installation/:installationId/reports', function(req,res) {
    if(req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
        res.status(401).json({reason: 'The user cannot perform that operation'});
        return;
    }

	const report = req.body;
    reportService.postReport(req, res, report);

})

app.get('/api/admin/reports', function(req,res){
    const {
        startDate,
        endDate,
        providerId,
    } = req.query;

    reportService.getAdminReports(startDate, endDate, providerId).then((reports) => {
        res.send(reports.map((report) => contracts.measureContract(report)));
    });
});

app.get('/api/admin/reports.csv', function(req,res){
    const {
        startDate,
        endDate,
        providerId,
    } = req.query;
    reportService.getAdminReports(startDate, endDate, providerId).then((reports) => {
        json2csv({ data: reports.toJSON(), fields: ['timestamp', 'upUsage', 'downUsage', 'upQuality', 'downQuality'] }, function(err, csv) {
            res.setHeader('Content-disposition', 'attachment; filename=data.csv');
            res.set('Content-Type', 'text/csv');
            res.status(200).send(csv);
        });
    });
});


app.listen(3001, function () {
  console.log('TiX api app listening on port 3001!')
});