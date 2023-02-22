//This is where we will add our auth strategies
import { Strategy, ExtractJwt } from "passport-jwt";

export default function setupJWTStrategy(passport) {
    passport.use(
        new Strategy({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: "thisIsASecret"
        }, function (payload, done) {
            try {
                return done(null, { username: payload.username, id: payload.id });
            } catch (e) {
                return done(e, null);
            }
        })
    )
}