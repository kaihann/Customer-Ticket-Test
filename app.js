const express = require('express');
const axios = require('axios');
const app = express();
const port = 3000;

// Add Winston logger
const winston = require('winston');
const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'connectivity.log' })
  ]
});

const config = {
  INGRESS_MODE: process.env.INGRESS_MODE || 'dual-stack',
  EGRESS_MODE: process.env.EGRESS_MODE || 'dual-stack',
  EC2_ENDPOINT: process.env.EC2_ENDPOINT,
  EC2_ENDPOINT_IPV6: process.env.EC2_ENDPOINT_IPV6,
  EC2_PORT: process.env.EC2_PORT || '80'
};

// Enhanced request logging middleware
const logRequest = (req, res, next) => {
  const requestData = {
    timestamp: new Date().toISOString(),
    sourceIp: req.ip,
    realIp: req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.ip,
    method: req.method,
    path: req.path,
    headers: req.headers,
    protocol: req.protocol,
    isIPv6: req.ip.includes(':')
  };

  logger.info('Incoming Request', requestData);

  // Capture response data
  const oldWrite = res.write;
  const oldEnd = res.end;
  const chunks = [];

  res.write = function (chunk) {
    chunks.push(chunk);
    return oldWrite.apply(res, arguments);
  };

  res.end = function (chunk) {
    if (chunk) chunks.push(chunk);
    
    const responseData = {
      timestamp: new Date().toISOString(),
      sourceIp: requestData.sourceIp,
      realIp: requestData.realIp,
      path: requestData.path,
      statusCode: res.statusCode,
      responseBody: Buffer.concat(chunks).toString('utf8')
    };

    logger.info('Response Sent', responseData);
    
    oldEnd.apply(res, arguments);
  };

  next();
};

app.use(express.json());
app.use(logRequest);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    config: {
      ingressMode: config.INGRESS_MODE,
      egressMode: config.EGRESS_MODE
    }
  });
});

// Modified test functions with logging
async function testInternetConnectivity() {  // Fixed: removed extra "sync"
  const results = {
    timestamp: new Date().toISOString(),
    ipv4: { success: false, error: null },
    ipv6: { success: false, error: null }
  };

  if (config.EGRESS_MODE !== 'ipv6') {
    try {
      logger.info('Testing IPv4 connectivity');
      const ipv4Response = await axios.get('https://api.ipify.org?format=json', {
        family: 4,
        timeout: 5000
      });
      results.ipv4 = {
        success: true,
        ip: ipv4Response.data.ip
      };
      logger.info('IPv4 test successful', { result: results.ipv4 });
    } catch (error) {
      results.ipv4.error = error.message;
      logger.error('IPv4 test failed', { error: error.message });
    }
  }

  if (config.EGRESS_MODE !== 'ipv4') {
    try {
      logger.info('Testing IPv6 connectivity');
      const ipv6Response = await axios.get('https://api64.ipify.org?format=json', {
        family: 6,
        timeout: 5000
      });
      results.ipv6 = {
        success: true,
        ip: ipv6Response.data.ip
      };
      logger.info('IPv6 test successful', { result: results.ipv6 });
    } catch (error) {
      results.ipv6.error = error.message;
      logger.error('IPv6 test failed', { error: error.message });
    }
  }

  return results;
}

async function testAuth0Connectivity() {
  const results = {
    timestamp: new Date().toISOString(),
    auth0: {
      ipv4: { success: false, error: null, responseTime: null },
      ipv6: { success: false, error: null, responseTime: null }
    }
  };

  // Test IPv4
  if (config.EGRESS_MODE !== 'ipv6') {
    try {
      logger.info('Testing Auth0 IPv4 connectivity');
      const startTime = Date.now();
      const response = await axios.get('https://himss-digitalradar.eu.auth0.com/.well-known/openid-configuration', {
        family: 4,
        timeout: 5000
      });
      const responseTime = Date.now() - startTime;

      results.auth0.ipv4 = {
        success: true,
        status: response.status,
        responseTime: responseTime,
        issuer: response.data.issuer
      };
      logger.info('Auth0 IPv4 test successful', { result: results.auth0.ipv4 });
    } catch (error) {
      results.auth0.ipv4.error = error.message;
      logger.error('Auth0 IPv4 test failed', { error: error.message });
    }
  }

  // Test IPv6
  if (config.EGRESS_MODE !== 'ipv4') {
    try {
      logger.info('Testing Auth0 IPv6 connectivity');
      const startTime = Date.now();
      const response = await axios.get('https://himss-digitalradar.eu.auth0.com/.well-known/openid-configuration', {
        family: 6,
        timeout: 5000
      });
      const responseTime = Date.now() - startTime;

      results.auth0.ipv6 = {
        success: true,
        status: response.status,
        responseTime: responseTime,
        issuer: response.data.issuer
      };
      logger.info('Auth0 IPv6 test successful', { result: results.auth0.ipv6 });
    } catch (error) {
      results.auth0.ipv6.error = error.message;
      logger.error('Auth0 IPv6 test failed', { error: error.message });
    }
  }

  return results;
}

async function testVpcConnectivity() {
  const results = {
    timestamp: new Date().toISOString(),
    ec2: {
      ipv4: { success: false, error: null },
      ipv6: { success: false, error: null }
    }
  };

  const ec2Url = `http://${config.EC2_ENDPOINT}:${config.EC2_PORT}/health`;
  const ec2UrlIPv6 = `http://[${config.EC2_ENDPOINT_IPV6}]:${config.EC2_PORT}/health`;

  if (config.EGRESS_MODE !== 'ipv6') {
    try {
      logger.info('Testing EC2 IPv4 connectivity', { url: ec2Url });
      const ipv4Response = await axios.get(ec2Url, {
        family: 4,
        timeout: 5000
      });
      results.ec2.ipv4 = {
        success: true,
        status: ipv4Response.status,
        data: ipv4Response.data
      };
      logger.info('EC2 IPv4 test successful', { result: results.ec2.ipv4 });
    } catch (error) {
      results.ec2.ipv4.error = error.message;
      logger.error('EC2 IPv4 test failed', { error: error.message });
    }
  }

  if (config.EGRESS_MODE !== 'ipv4') {
    try {
      logger.info('Testing EC2 IPv6 connectivity', { url: ec2UrlIPv6 });
      const ipv6Response = await axios.get(ec2UrlIPv6, {
        family: 6,
        timeout: 5000
      });
      results.ec2.ipv6 = {
        success: true,
        status: ipv6Response.status,
        data: ipv6Response.data
      };
      logger.info('EC2 IPv6 test successful', { result: results.ec2.ipv6 });
    } catch (error) {
      results.ec2.ipv6.error = error.message;
      logger.error('EC2 IPv6 test failed', { error: error.message });
    }
  }

  return results;
}

// Test endpoints
app.get('/test/internet', async (req, res) => {
  try {
    const results = await testInternetConnectivity();
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/test/vpc', async (req, res) => {
  try {
    const results = await testVpcConnectivity();
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/test/auth0', async (req, res) => {
  try {
    const results = await testAuth0Connectivity();
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/test/all', async (req, res) => {
  try {
    const [internetResults, vpcResults, auth0Results] = await Promise.all([
      testInternetConnectivity(),
      testVpcConnectivity(),
      testAuth0Connectivity()
    ]);

    res.json({
      timestamp: new Date().toISOString(),
      configuration: {
        ingressMode: config.INGRESS_MODE,
        egressMode: config.EGRESS_MODE,
        ec2Endpoint: config.EC2_ENDPOINT
      },
      internet: internetResults,
      vpc: vpcResults,
      auth0: auth0Results
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Define server options based on INGRESS_MODE
const serverOptions = {
  port: port
};

// Configure host based on INGRESS_MODE
switch (config.INGRESS_MODE) {
  case 'ipv4':
    serverOptions.host = '0.0.0.0';  // Correct IPv4 binding address
    break;
  case 'ipv6':
    serverOptions.host = '::';
    break;
  case 'dual-stack':
    serverOptions.host = '::';
    break;
  default:
    throw new Error(`Invalid INGRESS_MODE: ${config.INGRESS_MODE}`);
}

// Start the server
app.listen(serverOptions.port, serverOptions.host, () => {
  logger.info('Server started', {
    ingressMode: config.INGRESS_MODE,
    egressMode: config.EGRESS_MODE,
    ec2Endpoint: config.EC2_ENDPOINT,
    host: serverOptions.host,
    port: serverOptions.port
  });
});