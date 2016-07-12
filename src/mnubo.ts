import {base64Encode} from './utils/underscore';
import {http} from './http/http';
import {RequestOptions} from './http/request';

import {Owners} from './ingestion/owners';
import {Objects} from './ingestion/objects';
import {Events} from './ingestion/events';
import {Search} from './restitution/search';

export enum OAuth2Scopes {
  ALL,
  LIMITED,
  READ,
  WRITE
}

interface ClientOptions {
  id: string;
  secret: string;
  env: string;
  compression?: {
      request?: string, /* supported value are 'gzip' or 'deflate' */
      response?: string /* supported value are 'gzip' or 'deflate' */
  },
  httpOptions?: RequestOptions;
}

class AccessToken {
  private requestedAt: Date;

  constructor(public value: string, public type: string, public expiresIn: number, public jti: string) {
    this.requestedAt = new Date();
  }

  isValid() {
    var now = new Date();

    return now.getTime() < this.requestedAt.getTime() + this.expiresIn * 1000;
  }
}

export class Client {
  public owners: Owners;
  public objects: Objects;
  public events: Events;
  public search: Search;

  private token: AccessToken;

  constructor(public options: ClientOptions) {
    if (options.env === undefined) {
      options.env = 'sandbox';
    }

    if (!options.httpOptions) {
      options.httpOptions = {
        protocol: 'https',
        hostname: this.hostname(),
        port: 443
      };
    }

    this.owners = new Owners(this);
    this.objects = new Objects(this);
    this.events = new Events(this);
    this.search = new Search(this);
  }

  hostname(): string {
    let part = 'sandbox';

    if (this.options.env === 'production') {
      part = 'api';
    }

    return `rest.${part}.mnubo.com`;
  }

  getAccessToken(scope?: OAuth2Scopes): Promise<any> {
    scope = scope || OAuth2Scopes.ALL;

    const id = this.options.id;
    const secret = this.options.secret;
    const payload = `grant_type=client_credentials&scope=${OAuth2Scopes[scope].toUpperCase()}`;

    const options: RequestOptions = {
      path: '/oauth/token',
      headers: new Map<string, string>()
    };

    options.headers.set('Authorization', `Basic ${base64Encode(id + ':' + secret)}`);
    options.headers.set('Content-Type', 'application/x-www-form-urlencoded');
    options.headers.set('Accept-Encoding', 'application/json');

    Object.assign(options, this.options.httpOptions);

    const promise = http.post(options, payload);

    promise.then((data: any) => {
      this.token = new AccessToken(data.access_token, data.token_type, data.expires_in, data.jti);
    });

    return promise;
  }

  /**
   * Is the access token still valid?

   * @return {boolean} false if there is no access token or if it has expired.
   */
  isAccessTokenValid(): boolean {
    return (this.token && this.token.isValid());
  }

  authenticate(): Promise<any> {
    if (this.isAccessTokenValid()) {
      return Promise.resolve(this.token);
    } else {
      return this.getAccessToken().then(() => {
        return this.token;
      });
    }
  }

  buildHttpOptions(path: string, contentType?: string): RequestOptions {
    const options: RequestOptions = {
      path: path,
      headers: new Map<string, string>()
    };

    contentType = contentType || 'application/json';

    if (this.options.compression) {
        if (this.options.compression.request) {
            options.headers.set('Content-Encoding', this.options.compression.request);
        }

        if (this.options.compression.response) {
            options.headers.set('Accept-Encoding', this.options.compression.response);
        }
    }

    options.headers.set('Authorization', `Bearer ${this.token.value}`);
    options.headers.set('Content-Type', `${contentType}`);

    Object.assign(options, this.options.httpOptions);

    return options;
  }

  get(path: string, contentType?: string) {
    return http.get(this.buildHttpOptions(path, contentType));
  }

  post(path: string, payload: any, contentType?: string) {
    return http.post(this.buildHttpOptions(path, contentType), payload);
  }

  put(path: string, payload: any, contentType?: string) {
    return http.put(this.buildHttpOptions(path, contentType), payload);
  }

  delete (path: string, contentType?: string) {
    return http.delete(this.buildHttpOptions(path, contentType));
  }
}
