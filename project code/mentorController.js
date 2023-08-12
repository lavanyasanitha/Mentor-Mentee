const Mentor = require('../models/mentorModel');
const catchAsync = require('../utils/catchAsync');
const factory = require('./handlerFactory');
//const AppError = require('../utils/appError');

exports.aliasTopMentors = (req, res, next) => {
  req.query.limit = '5';
  req.query.sort = '-ratingsAverage,price';
  req.query.fields = 'name,price,ratingsAverage,skills';
  next();
};

exports.getAllMentors = factory.getAll();
exports.getMentor = factory.getOne(Mentor, { path: 'reviews' });
//exports.createMentor = factory.createOne(Mentor);
exports.updateMentor = factory.updateOne(Mentor);
exports.deleteMentor = factory.deleteOne(Mentor);

exports.createMentor = async (req, res) => {
  try {
    console.log(req.body);
    const doc = await Mentor.create(req.body);
    res.status(201).json({
      status: 'success',
      data: {
        data: doc
      }
    });
  } catch (err) {
    console.log(err);
  }
};

exports.deleteMentorProfile = factory.deleteOne(Mentor);

exports.sendmessage = catchAsync(async (req, res, next) => {
  console.log(req.body);
  console.log('mail send message');
});

exports.getMentorStats = catchAsync(async (req, res, next) => {
  const stats = await Mentor.aggregate([
    {
      $match: { ratingsAverage: { $gte: 4.5 } }
    },
    {
      $group: {
        _id: { $toUpper: '$country' },
        numTours: { $sum: 1 },
        numRatings: { $sum: '$ratingsQuantity' },
        avgRating: { $avg: '$ratingsAverage' },
        avgPrice: { $avg: '$price' },
        minPrice: { $min: '$price' },
        maxPrice: { $max: '$price' }
      }
    },
    {
      $sort: { avgPrice: 1 }
    }
    // {
    //   $match: { _id: { $ne: 'EASY' } }
    // }
  ]);

  res.status(200).json({
    status: 'success',
    data: {
      stats
    }
  });
});
