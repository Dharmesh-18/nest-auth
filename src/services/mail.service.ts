import * as nodemailer from 'nodemailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      auth: {
        user: 'troy90@ethereal.email',
        pass: '5eFBKAdCXD38U7yENJ',
      },
    });
  }
  async sendPasswordResetEmail(to: string, token: string) {
      const resetLink = `http://localhost:3000/reset-password?token=${token}`;
      const mailOptions = {
          from : 'Auth-backend sevice',
          to: to,
          subject: 'Password Reset Request',
          html: `<p>You requested a password reset. Click the link below to reset your password:</p><p><a href="${resetLink}" target="_blank" rel="noopener noreferrer">Reset Password</a></p><p>If you did not request this, please ignore this email.</p>`,
      };
      await this.transporter.sendMail(mailOptions);
  }
}

