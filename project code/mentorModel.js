const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
// const User = require('./userModel');
// const validator = require('validator');

const mentorSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'please provide your name'],
      trim: true,
      maxlength: [40, 'A tour name must have less or equal then 40 characters'],
      minlength: [5, 'A tour name must have more or equal then 5 characters']
      // validate: [validator.isAlpha, 'Tour name must only contain characters']
    },
    slug: String,
    duration: {
      type: Number,
      required: [true, 'A tour must have a duration']
    },
    ratingsAverage: {
      type: Number,
      default: 4.5,
      min: [1, 'Rating must be above 1.0'],
      max: [5, 'Rating must be below 5.0'],
      set: val => Math.round(val * 10) / 10 // 4.666666, 46.6666, 47, 4.7
    },
    ratingsQuantity: {
      type: Number,
      default: 0
    },
    price: {
      type: Number,
      required: [true, 'A tour must have a price']
    },
    priceDiscount: {
      type: Number,
      validate: {
        validator: function(val) {
          // this only points to current doc on NEW document creation
          return val < this.price;
        },
        message: 'Discount price ({VALUE}) should be below regular price'
      }
    },
    company: {
      type: String,
      trim: true
    },
    description: {
      type: String,
      trim: true,
      required: [true, 'A mentor must have a description']
    },
    profession: {
      type: String,
      trim: true,
      required: [true, 'A mentor must have a description']
    },
    country: {
      type: String,
      trim: true,
      required: [true, 'A mentor must have a country']
    },
    languages: {
      type: String,
      trim: true,
      required: [true, 'A mentor must specify the languages he can speak']
    },
    skills: {
      type: String,
      trim: true
    },
    email: {
      type: String,
      required: [true, 'A mentor must provide email'],
      unique: true
    },
    imageCover: {
      type: String,
      default: 'venkatesh.png'
    },
    secretMentor: {
      type: Boolean,
      default: true
    },
    verified: {
      type: Boolean,
      defualt: false
    },
    password: {
      type: String,
      required: true
    },
    status: {
      type: String,
      default: 'notavailable',
      required: true
    },
    passwordConfirm: {
      type: String,
      required: [true, 'Please confirm your password'],
      validate: {
        // This only works on CREATE and SAVE!!!
        validator: function(el) {
          return el === this.password;
        },
        message: 'Passwords are not the same!'
      }
    }
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

mentorSchema.pre('save', async function(next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

mentorSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

mentorSchema.pre(/^find/, function(next) {
  // this points to the current query
  this.find({ active: { $ne: false } });
  this.find({ verified: { $ne: true } });
  next();
});

mentorSchema.methods.correctPassword = async function(
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

mentorSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }

  // False means NOT changed
  return false;
};

mentorSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  console.log({ resetToken }, this.passwordResetToken);

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

// QUERY MIDDLEWARE
// mentorSchema.pre('find', function(next) {
mentorSchema.pre(/^find/, function(next) {
  this.find({ secretMentor: { $ne: true } });

  this.start = Date.now();
  next();
});

const Mentor = mongoose.model('Mentor', mentorSchema);

module.exports = Mentor;
