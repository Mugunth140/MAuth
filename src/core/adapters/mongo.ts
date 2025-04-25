import mongoose from 'mongoose';

interface IUser {
  email: string;
  password: string;
}

const userSchema = new mongoose.Schema<IUser>({
  email: String,
  password: String,
});

const User = mongoose.model<IUser>('User', userSchema);

export const connectMongo = async () => {
  await mongoose.connect(process.env.DB_URL as string);
};

export const createUser = async (data: IUser) => {
  return new User(data).save();
};

export const findUserByEmail = async (email: string) => {
  return User.findOne({ email });
};
