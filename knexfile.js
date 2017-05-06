module.exports = {

  development: {
  	pool:{
  		max:1
	},
    client: 'mysql',
    connection: {
	    host     : '127.0.0.1',
	    user     : 'tix',
	    password : 'tix',
	    database : 'tix',
	    charset  : 'utf8'
  	},
  }
}