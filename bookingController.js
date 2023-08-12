const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const Mentor = require('../models/mentorModel');
//const User = require('../models/userModel');
const Booking = require('../models/bookingModel');
const catchAsync = require('../utils/catchAsync');
const factory = require('./handlerFactory');

exports.getCheckoutSession = catchAsync(async (req, res, next) => {
  // 1) Get the currently booked tour
  const mentor = await Mentor.findById(req.params.mentorId);
  const Price = mentor.price;
  console.log(Price);
  const { mentorId } = req.params;
  const transformedItems = {
    quantity: 1,
    price_data: {
      currency: 'usd',
      unit_amount: Math.round(mentor.price * 100),
      product_data: {
        name: mentor.name,
        description: mentor.description
      }
    }
  };
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    success_url: `${req.protocol}://${req.get('host')}/?mentor=${mentorId}&user=${req.user.id}&price=${Price}`,
    cancel_url: `${req.protocol}://${req.get('host')}/mentor/${mentorId}`,
    customer_email: req.user.email,
    client_reference_id: req.params.tourId,
    line_items: [transformedItems],
    mode: 'payment'
  });
  // 3) Create session as response
  res.status(200).json({
    status: 'success',
    session
  });
});
exports.createBookingCheckout = catchAsync(async (req, res, next) => {
  const { mentor, user, price } = req.query;

  if (!mentor && !user && !price) return next();
  await Booking.create({ mentor, user, price });

  res.redirect(req.originalUrl.split('?')[0]);
});

exports.myBookings = catchAsync(async (req, res, next) => {
  const userId = req.user.id;
  const result = await Booking.find({ user: userId });
  console.log(result);
  res.status(200).json({
    status: 'success',
    result
  });
});

exports.createBooking = factory.createOne(Booking);
exports.getBooking = factory.getOne(Booking);
exports.getAllBookings = factory.getAll(Booking);
exports.updateBooking = factory.updateOne(Booking);
exports.deleteBooking = factory.deleteOne(Booking);
