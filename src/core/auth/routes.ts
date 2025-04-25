import { Router, Request, Response, RequestHandler } from 'express';
import bcrypt from 'bcrypt';
import { createUser, findUserByEmail } from '../adapters/mongo';
import { generateToken } from '../services/jwtService';

const router = Router();

router.post('/register', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const user = await createUser({ email, password: hash });
  res.status(201).json({ message: 'Registered', user });
});

const loginHandler: RequestHandler = async (req, res): Promise<void> => {
  const { email, password } = req.body;
  const user = await findUserByEmail(email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    res.status(401).json({ message: 'Invalid credentials' });
    return;
  }
  const token = generateToken(user._id.toString());
  res.json({ token });
};
router.post('/login', loginHandler);

export default router;
