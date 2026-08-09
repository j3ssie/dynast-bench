import 'reflect-metadata';
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import RedisStore from 'connect-redis';
import { createClient } from 'redis';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { logger: ['error', 'warn', 'log'] });
  const expressApp = app.getHttpAdapter().getInstance();
  expressApp.set('trust proxy', false);
  app.enableCors({ origin: ['http://127.0.0.1:3000'], credentials: true });
  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true, forbidNonWhitelisted: true }));
  app.use(cookieParser());

  let store: any = undefined;
  const redisUrl = process.env.REDIS_URL || 'redis://redis:6379';
  try {
    const redisClient = createClient({ url: redisUrl });
    redisClient.on('error', () => undefined);
    await redisClient.connect();
    store = new (RedisStore as any)({ client: redisClient, prefix: 'sess:' });
  } catch (_) {
    store = undefined;
  }

  app.use(
    session({
      store,
      name: 'bench.sid',
      secret: process.env.SESSION_SECRET || 'benchsecret',
      resave: false,
      saveUninitialized: true,
      cookie: { httpOnly: true, sameSite: 'lax', secure: false },
    }),
  );

  await app.listen(3001, '0.0.0.0');
}
bootstrap();
