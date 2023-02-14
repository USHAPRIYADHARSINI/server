import { client } from '../index.js';


export async function CreateUser(data) {
    return await client.db('forgotpassword').collection('users').insertOne(data);
}

export async function getUserByName(email) { 
    return await client.db('forgotpassword').collection('users').findOne({email:email});
}

export async function getUserByEmail(email) {
    return await client.db('forgotpassword').collection('users').findOne({email:email});
}