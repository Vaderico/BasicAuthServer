const passport = require('passport');
const Authentication = require('../controllers/authentication');
const passportService = require('../services/passport');

const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', { session: false });
const requireGoogle = passport.authenticate('google', { session: false });
const requireFacebook = passport.authenticate('facebook', { session: false });

module.exports = app => {
  app.post('/auth/signin', requireSignin, Authentication.signin);

  app.post('/auth/signup', Authentication.signup);

  app.get(
    '/auth/google',
    passport.authenticate('google', {
      scope: ['profile', 'email']
    })
  );

  app.get('/auth/google/callback', requireGoogle, Authentication.signin);

  app.get('/auth/facebook', passport.authenticate('facebook'));

  app.get('/auth/facebook/callback', requireFacebook, Authentication.signin);

  app.get('/', requireAuth, (req, res) => {
    res.send({ hi: 'there' });
  });
};
