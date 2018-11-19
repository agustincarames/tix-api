FROM node:boron

# Install python dependencies
RUN apt-get update \
	&& apt-get install python-setuptools python-dev build-essential -y \
	&& easy_install pip \
	&& pip install mysqlclient

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package.json .
RUN npm install

# Bundle app source
COPY . .

EXPOSE 3001

CMD ["npm", "start"]
