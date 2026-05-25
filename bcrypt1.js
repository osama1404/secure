const bcrypt=require('bcrypt')

let username="Madallah"
let password="admin123"
const saltRound=10;
const hashPass="";

bcrypt.hash(password,saltRound,(err,hashPass)=>{
   if(err){
    console.log("Error in Hashing")
    return;
   } 
   console.log('Hashing Password:', hashPass)
   password="admin1234"
   bcrypt.compare(password,hashPass,(err,result)=>{
    if(err){
        console.log("Error in Hashing")
        return;
       } 
       if (result){
        console.log("Correct password")
       }else{
        console.log("Not Correct password")
       }
   })
})
//console.log('Hashing Password:', hashPass)