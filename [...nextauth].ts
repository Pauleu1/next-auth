import NextAuth, { NextAuthOptions } from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import jwt from "jsonwebtoken";


let userAccount = null;
const prisma = new PrismaClient();

const confirmPasswordHash = (plainPassword, hashedPassword) => {
  return new Promise(resolve => {
      bcrypt.compare(plainPassword, hashedPassword, function(err, res) {
          resolve(res);
      });
  })
}

// For more information on each option (and a full list of options) go to
// https://next-auth.js.org/configuration/options
export const authOptions: NextAuthOptions = {
  // https://next-auth.js.org/configuration/providers/oauth
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "credentials",
      credentials: {},
      async authorize(credentials: any) {
          try
          {
              const user = await prisma.users.findFirst({
                  where: {
                      email: credentials.email
                  }
              });

              if (user !== null)
              {
                  //Compare the hash
                  const res = await confirmPasswordHash(credentials.password, user.password);
                  if (res === true)
                  {
                      userAccount = {
                          userId: user.userId,
                          firstName: user.firstName,
                          lastName: user.lastName,
                          email: user.email,
                          isActive: user.isActive
                      };
                      return userAccount;
                  }
                  else
                  {
                      console.log("Hash not matched logging in");
                      return null;
                  }
              }
              else {
                  return null;
              }
          }
          catch (err)
          {
              console.log("Authorize error:", err);
          }

      }
  })
  ],
  session: {
    // Choose how you want to save the user session.
    // The default is `"jwt"`, an encrypted JWT (JWE) stored in the session cookie.
    // If you use an `adapter` however, we default it to `"database"` instead.
    // You can still force a JWT session by explicitly defining `"jwt"`.
    // When using `"database"`, the session cookie will only contain a `sessionToken` value,
    // which is used to look up the session in the database.
    strategy: "jwt",
  
    // Seconds - How long until an idle session expires and is no longer valid.
    maxAge: 30 * 24 * 60 * 60, // 30 days
  
    // Seconds - Throttle how frequently to write to database to extend a session.
    // Use it to limit write operations. Set to 0 to always update the database.
    // Note: This option is ignored if using JSON Web Tokens
    updateAge: 24 * 60 * 60, // 24 hours
  },
  jwt: {
    secret: process.env.HASURA_GRAPHQL_JWT_SECRET,
    encode: async ({ secret, token, maxAge }) => {
      const jwtClaims = {
        "sub": token.id.toString() ,
        "name": token.name ,
        "email": token.email,
        "iat": Date.now() / 1000,
        "exp": Math.floor(Date.now() / 1000) + (24*60*60),
        "https://hasura.io/jwt/claims": {
          "x-hasura-allowed-roles": ["user"],
          "x-hasura-default-role": "user",
          "x-hasura-role": "user",
          "x-hasura-user-id": token.id,
        }
      };
      const encodedToken = jwt.sign(jwtClaims, secret, { algorithm: 'HS256'});
      return encodedToken;
    },
    decode: async ({ secret, token }) => {
      console.log(token)
      const decodedToken = jwt.verify({token: token}, {secretOrPublicKey: secret });
      return decodedToken;
 },


  },
  callbacks: {
    async session(session, token) { 
      const encodedToken = jwt.sign(token, process.env.HASURA_GRAPHQL_JWT_SECRET, { algorithm: 'HS256'});
      session.id = token.id;
      session.token = encodedToken;
      return Promise.resolve(session);
    },
    async jwt(token, user, account, profile, isNewUser) { 
      const isUserSignedIn = user ? true : false;
      
      if(isUserSignedIn) {
        token.id = user.id.toString();
      }
      return Promise.resolve(token);
    }
  },
}

export default NextAuth(authOptions)
