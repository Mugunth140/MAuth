import express from 'express';
import dotenv from 'dotenv';
import authRoutes from './auth/routes';
import { connectMongo } from './adapters/mongo';

dotenv.config();

export const setupMAuth = async (app: express.Express) => {
  await connectMongo();
  app.use(express.json());
  app.use('/auth', authRoutes);
};

