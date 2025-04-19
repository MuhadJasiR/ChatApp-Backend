import { Request,Response } from "express";
import bcrypt, { compare } from "bcrypt";
import pool from "../models/db";
import jwt from "jsonwebtoken";
import { error } from "console";


const SALT_ROUNDS =10;
const JWT_SECRET = process.env.JWT_SECRET || "chatSecretKey"

export const register = async(req: Request, res: Response)=>{
    // 1. get username, email, password
    // 2. Insert those data into our db
    // 3. return message user
    const{username,email,password} = req.body;
    try{
        const hashedPassword = await bcrypt.hash(password,SALT_ROUNDS);
        const result = await pool.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *',
            [username, email, hashedPassword]
        );
        const user = result.rows[0];
        res.status(201).json({message:"User registered successfully",user})
    }catch(error){
        console.error('Registration error:', error);
        res.status(500).json({
            error: "Failed to register user",
            details: error instanceof Error ? error.message : 'Unknown error'
        });
    }
}

export const login = async(req: Request, res: Response): Promise<any>=>{
    // 1. get email,password
    // 2. Verify if email exist
    // 3. compare pwd -> "invalid credentials"
    // 4. return token
    const {email,password }= req.body;
    try {
        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1",[email]
        );
        const user = result.rows[0];
        if(!user) return res.status(404).json({error:'User not fount'});

        const isMatch = await bcrypt.compare(password,user.password);
        if(!isMatch)return res.status(400).json({error:"Invalid credential"});


        const token = jwt.sign({id:user.id},JWT_SECRET,{expiresIn:"10h"});
        res.json({message:"Logged in successfully", token});
    } catch (error) {
        res.status(500).json({error:"Failed to log in"});
    }
}