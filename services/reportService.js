var Measure = require('../models/Measure');
var Provider = require('../models/Provider');
var LocationProvider = require('../models/LocationProvider');
var PythonShell = require('python-shell');

var getAdminReports = (startDate, endDate, providerId) => {
    return this.getReports(null, null, providerId, startDate, endDate);
}

var postReport = (req, res, report) => {
    var options = {
        scriptPath: 'ipToas',
        args: [report.ip]
    };

    PythonShell.run('info.py', options, function (err, result) {
        if(err) res.status(500).send('Could not calculate ipToAs');

        const as = result[0].split(',')[0];
        Provider.where('name', as).fetch().then((provider) => {
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
}

var getReports = (userId, installationId, providerId, startDate, endDate) => {
    var query = Measure;
    if(userId) {
        query = query.where('user_id', userId);
    }
    if(installationId){
        query = query.where('location_id', installationId);
    }
    if(providerId && providerId > 0){
        query = query.where('provider_id', providerId);
    }
    if(startDate){
        query = query.where('timestamp', '>' , startDate);
    }
    if(endDate){
        query = query.where('timestamp', '<', endDate);
    }
    return query.fetchAll();
}

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
    }).save().then((measure) => res.send(contracts.measureContract(measure)));
}

module.exports = {
    getAdminReports: getAdminReports,
    postReport: postReport,
    getReports: getReports,
};