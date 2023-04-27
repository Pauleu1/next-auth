import NextAuth from "next-auth"
import { PrismaClient } from '@prisma/client'
import CredentialsProvider from "next-auth/providers/credentials"
import jwt from "jsonwebtoken";

let userAccount = null;
const prisma = new PrismaClient();

const bcrypt = require('bcrypt');

const confirmPasswordHash = (plainPassword, hashedPassword) => {
    return new Promise(resolve => {
        bcrypt.compare(plainPassword, hashedPassword, function(err, res) {
            resolve(res);
        });
    })
}

export default NextAuth({
  providers: [
    CredentialsProvider({
        id: "credentials",
        name: "credentials",
        credentials: {},
        async authorize(credentials) {
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
    }),
],
  secret: process.env.HASURA_GRAPHQL_JWT_SECRET,

  session: {

    maxAge: 24*60*60
  },

  jwt: {
    secret: process.env.HASURA_GRAPHQL_JWT_SECRET,
    encode: async ({ secret, token }) => {
      const jwtClaims = {
        //"sub": token.sub.toString() ,
        "userId": token.user.userId,
        "firstname": token.user.firstName,
        "email": token.user.email,
        "isActive" : token.user.isActive,
        "iat": Date.now() / 1000,
        "exp": Math.floor(Date.now() / 1000) + (24*60*60),
        "https://hasura.io/jwt/claims": {
          "x-hasura-allowed-roles": ["azubi"],
          "x-hasura-default-role": "azubi",
          "x-hasura-role": "azubi",
          "x-hasura-user-id": token.user.userId,
        }
      };

      const encodedToken = jwt.sign({payload: jwtClaims}, secret, { algorithm: 'HS256'});
      //console.log(encodedToken)
      return encodedToken;
    },
    decode: async ({ secret, token, maxAge }) => {
      const decodedToken = jwt.verify(token, secret, { algorithms: ['HS256']});
      return decodedToken;
    },
  },
  pages: {
  },

  callbacks: {
    async register(firstName, lastName, email, password) {
        try
        {
            await prisma.users.create({
                data: {
                    firstName: firstName,
                    lastName: lastName,
                    email: email,
                    password: password
                }
            })
            return true;
        }
        catch (err)
        {
            console.error("Failed to register user. Error", err);
            return false;
        }

    },
    async signIn(user, account, profile) {
        try
        {
            //the user object is wrapped in another user object so extract it
            user = user.user;
            //console.log("Sign in callback", user);
            if (typeof user.userId !== typeof undefined)
            {

                if (user.isActive === true)
                {
                    console.log("User is active");
                    return user;
                }
                else
                {
                    console.log("User is not active")
                    return false;
                }
            }
            else
            {
                console.log("User id was undefined")
                return false;
            }
        }
        catch (err)
        {
            console.error("Signin callback error:", err);
        }

    },
    async session(session, token, payload) { 
        console.log(session)
    token = session.token
    payload = token.token.payload
      const encodedToken = jwt.sign({payload: payload}, process.env.HASURA_GRAPHQL_JWT_SECRET, { algorithm: 'HS256'});
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

  events: {},

  debug: true,
})
