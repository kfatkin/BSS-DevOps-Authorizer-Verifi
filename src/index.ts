import * as jwt from 'jsonwebtoken';
import * as moment from 'moment';
import * as AWS from 'aws-sdk';

const Logger = {
  // tslint:disable-next-line: no-console
  console: console.log,
};

const MAX_DURATION = 300;
const MAX_FUTURE_DURATION = 60;

export class VerifiAuthorizer {
  private _event;
  private _context;
  private _secret;

  constructor(event, context) {
    this._event = event;
    this._context = context;
  }

  async getSecret() {
    const ssm = new AWS.SSM({ region: process.env.AWS_REGION });
    const secret = ssm
      .getParameter({ Name: '/BSS/DevOps/Verifi/Secret', WithDecryption: true })
      .promise();
    this._secret = (await secret).Parameter.Value;
    return this._secret;
  }

  generatePolicy(effect) {
    const principalId = 'Id' + new Date().getTime();
    const response = { principalId: principalId, policyDocument: null };
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [],
    };
    const statementOne = {
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource: this._event.methodArn,
    };
    policyDocument.Statement[0] = statementOne;
    response.policyDocument = policyDocument;
    return response;
  }

  isValid() {
    try {
      const token = this._event.authorizationToken;
      const tokenInfo = token.split(' ');
      const type: string = tokenInfo[0];
      if (type.trim().toLowerCase() !== 'bearer') return false;
      const response: any = jwt.verify(tokenInfo[1].trim(), this._secret, {
        complete: true,
        ignoreExpiration: false,
      });
      if (this.isResposneValid(response)) {
        if (this.isPayloadValid(response.payload)) {
          return true;
        }
      }
      return false;
    } catch (error) {
      this.logError(error);
      return false;
    }
  }

  private logError(error) {
    if (error.message) {
      Logger.console(error.message);
    } else {
      Logger.console(error);
    }
  }

  private isResposneValid(response) {
    try {
      if (typeof response !== 'object') return false;
      if (
        response.header &&
        response.payload &&
        response.payload.exp &&
        response.payload.iat
      ) {
        return true;
      }
      return false;
    } catch (error) {
      return false;
    }
  }

  private isPayloadValid(payload) {
    try {
      const now = moment.utc();
      const iat = moment.unix(payload.iat);
      const exp = moment.unix(payload.exp);
      const iatDuration = iat.diff(now, 'seconds');
      const expDuration = exp.diff(iat, 'seconds');
      Logger.console(iatDuration, expDuration);
      if (iatDuration < -MAX_DURATION) {
        const message = `iat more than ${MAX_DURATION}secs in the past`;
        Logger.console('ERROR', message);
        return false;
      } else if (iatDuration > MAX_FUTURE_DURATION) {
        const message = `iat more than ${MAX_FUTURE_DURATION}secs in the future`;
        Logger.console('ERROR', message);
        return false;
      }
      if (expDuration > MAX_DURATION) {
        const message = `exp more than ${MAX_DURATION}secs in the future from iat`;
        Logger.console('ERROR', message);
        return false;
      }
      return true;
    } catch (error) {
      return false;
    }
  }

  static async handler(event, context, callback) {
    const authorizer = new VerifiAuthorizer(event, context);
    await authorizer.getSecret();
    if (authorizer.isValid()) {
      return authorizer.generatePolicy('Allow');
    } else {
      callback('Unauthorized');
    }
  }
}

exports.handler = VerifiAuthorizer.handler;
