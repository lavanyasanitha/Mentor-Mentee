const Mentor = require('../models/mentorModel');
const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

exports.getOverview = catchAsync(async (req, res, next) => {
  // 1) Get tour data from collection
  const mentors = await Mentor.find();

  // 2) Build template
  // 3) Render that template using tour data from 1)
  res.status(200).render('overview', {
    title: 'All Mentors',
    mentors
  });
});

exports.getMentor = catchAsync(async (req, res, next) => {
  // 1) Get the data, for the requested tour (including reviews and guides
  const mentor = await Mentor.findOne({ _id: req.params.id }).populate({
    path: 'reviews',
    fields: 'review rating user'
  });

  if (!mentor) {
    return next(new AppError('There is no mentor with that name.', 404));
  }

  // 2) Build template
  // 3) Render template using data from 1)
  res.status(200).render('mentor', {
    title: `${mentor.name} Mentor`,
    mentor
  });
});

exports.getLoginForm = (req, res) => {
  res.status(200).render('login', {
    title: 'Log into your account'
  });
};
exports.getMentorLoginForm = (req, res) => {
  res.status(200).render('mentorlog', {
    title: 'Log into your account'
  });
};

exports.ReportMentor = catchAsync(async (req, res, next) => {
  // 1) Get the data, for the requested tour (including reviews and guides
  const mentor = await Mentor.findOne({ _id: req.params.id });

  if (!mentor) {
    return next(new AppError('There is no mentor with that name.', 404));
  }

  // 2) Build template
  // 3) Render template using data from 1)
  res.status(200).render('report', {
    title: `${mentor.name} Mentor`,
    mentor
  });
});

exports.getSignUpForm = (req, res) => {
  res.status(200).render('signup', {
    title: 'signUp into your account'
  });
};

exports.createMentor = (req, res) => {
  res.status(200).render('creatementor', {
    title: 'create mentor account'
  });
};

exports.admin = async (req, res) => {
  const mentors = await Mentor.find();

  // 2) Build template
  // 3) Render that template using tour data from 1)
  res.status(200).render('admin', {
    title: 'All Mentors',
    mentors
  });
};

exports.mentordetails = async (req, res) => {
  const user = await Mentor.findOne({ email: req.params.email });
  res.status(200).render('mentordetails', {
    user
  });
};

exports.getAccount = (req, res) => {
  res.status(200).render('account', {
    title: 'Your account'
  });
};

exports.updateUserData = catchAsync(async (req, res, next) => {
  const updatedUser = await User.findByIdAndUpdate(
    req.user.id,
    {
      name: req.body.name,
      email: req.body.email
    },
    {
      new: true,
      runValidators: true
    }
  );

  res.status(200).render('account', {
    title: 'Your account',
    user: updatedUser
  });
});
