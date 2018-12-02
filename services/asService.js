var NameNodes = require('../models/NameNodes.js')

// SELECT * FROM routerviews AS rv LEFT JOIN masks ON rv.mask = masks.prefix LEFT JOIN namenodes ON noden = noderouter WHERE 24978682 & masks.bits = rv.bin_ip_router ORDER BY prefix DESC LIMIT 1

var getASName = (ip) => {
    const ipBin = ip.split('.')
        .map((x) => x * 1)
        .reduce((l,r) => 256 * l + r);

    return NameNodes.query((qb) => {
        qb.innerJoin('routerviews', 'namenodes.noden', 'routerviews.noderouter')
            .innerJoin('masks', 'routerviews.mask', 'masks.prefix')
            .whereRaw('routerviews.bin_ip_router = masks.bits & ?', ipBin)
            .orderBy('masks.prefix', 'desc')
            .limit(1)
    }).fetch();
}

module.exports = {
    getASName: getASName
};
