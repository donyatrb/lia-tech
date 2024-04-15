<?php

namespace App\Modules\Auth\Controllers;

use App\Modules\Auth\Requests\RegisterRequest;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $credentials = $request->only('email', 'password');
        $token = auth()->guard('api')->attempt($credentials);

        if (!$token) {
            return response()->json([
                'message' => 'Unauthorized',
            ], 401);
        }

        $user = auth()->guard('api')->user();
        return response()->json([
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'bearer',
                'expires_in' => auth()->guard('api')->factory()->getTTL() * 60
            ]
        ],200);
    }

    public function register(RegisterRequest $request)
    {
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        if(!$user){
            return response()->json([
                'success' => false,
            ], 409);
        }

        return response()->json([
            'message' => 'User created successfully',
            'user' => $user
        ],201);
    }

    public function logout()
    {
        $removeToken = JWTAuth::invalidate(JWTAuth::getToken());
        if($removeToken){
            return response()->json([
                'message' => 'Successfully logged out',
            ]);
        }else{
            return response()->json([
                'success' => false,
                'message' => 'Failed logged out',
            ], 409);
        }
    }

    public function refresh()
    {
        $token = auth()->guard('api')->refresh();
        if($token){
            return response()->json([
                'user' => auth()->guard('api')->user(),
                'authorization' => [
                    'token' => $token,
                    'type' => 'bearer',
                    'expires_in' => auth()->factory()->getTTL() * 60
                ]
            ]);
        }else{
            return response()->json([
                'success' => false,
                'message' => 'Failed refresh token',
            ], 409);
        }
    }
}
