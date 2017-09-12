var Measure = require('../models/Measure');
var Provider = require('../models/Provider');
var LocationProvider = require('../models/LocationProvider');
var PythonShell = require('python-shell');

var getAdminReports = (startDate, endDate, providerId) => {
    return getReports(null, null, providerId, startDate, endDate);
}

var postReport = (report, as, installationId, userId) => {
    return Provider.where('name', as).fetch().then((provider) => {
        if(!provider){
            return Provider.forge({
                name: as
            }).save().then((provider) => {
                return createReport(report, provider.id, installationId, userId);
            })
        } else {
            return createReport(report, provider.id, installationId, userId);
        }
    })
}

function createReport(report, provider_id, installation_id, user_id){
    LocationProvider.where({location_id: installation_id, provider_id: provider_id}).fetch().then((relation) => {
        if(!relation){
            LocationProvider.forge({location_id: installation_id, provider_id: provider_id}).save();
        }
    });
    return Measure.forge({
        upUsage: report.upUsage,
        downUsage: report.downUsage,
        upQuality: report.upQuality,
        downQuality: report.downQuality,
        timestamp: new Date(report.timestamp * 1000),
        location_id: installation_id,
        provider_id: provider_id,
        user_id: user_id
    }).save();
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
        query = query.where('timestamp', '>=' , startDate);
    }
    if(endDate){
        query = query.where('timestamp', '<=', endDate);
    }
    return query.fetchAll();
}

module.exports = {
    getAdminReports: getAdminReports,
    postReport: postReport,
    getReports: getReports,
};