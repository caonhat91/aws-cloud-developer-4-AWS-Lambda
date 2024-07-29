import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const jwksUrl = 'https://dev-teuk6q6613po2us2.us.auth0.com/.well-known/jwks.json'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJQoNHFS2NaNDQMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi10ZXVrNnE2NjEzcG8ydXMyLnVzLmF1dGgwLmNvbTAeFw0yNDA3Mjkw
MzI0MDlaFw0zODA0MDcwMzI0MDlaMCwxKjAoBgNVBAMTIWRldi10ZXVrNnE2NjEz
cG8ydXMyLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKDvhbtTgDsY4F3G3UVqnYgG5QsjJUJRdDPXQGzvtjG5Dz0I6U1XG06cl178
eunj0Z4V5TwRX61PYsNepsuot/5kyOAnjVGdkiLN1p7fx7LWvVJAQsLVdDl1lGpO
4Eu6tiJ7f1f0an6AQyQtVxYc6uYzXFVP+I41RcSxBGUSlkvQ05FnrzERGhx6Nk8i
ufVwnKL6JxKMoAKONZdCYJuMEkIMUtEXvYJnz0qT5/rkOyI7/jrom3CwTpUifg2E
C3gHpZDPVPv/BYREggzUDXkDhApLL1ot21TmsNS6VJ+DOeif4DtpUxe0KZIpdU7S
kVCVBrn8yJ62YkzCIhp40GuBrgkCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUEj8EqyqExLATyS8Bi5Gdn+oI0howDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQBfkSzJO9gq5ZhpEVE7Y2gER/txN/G6FFwPZbt7XE2a
TuDnDrOIH/4ZL+HF7yYooK+bFuaOq3hX3yO0fiODddHOjNHrQwcYTff0NeYLbQXw
xH31K7gWN3QARCPG0YXfzz5hhulmbvQwSxavzzjM3JjMIPsdVEfolbfHrwDO9wnB
Ix3Igb/GldqRhO3Q0oO68EmGxQAmkgl60zZ1y1nbFc8rtDJpDIM9KjlFhBDtoTRC
dW9h9Q65pxioN5Q0HOYC6BV8N0J2SiEpDki4XVOSlUuUTsmLyRbO9J5sno2NXXNz
jGRbk6MR7upBjdvAyNMk/pvesQEwrc7s7FX+JulMNgwe
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  // TODO: Implement token verification
  jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
  return jwt;
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
