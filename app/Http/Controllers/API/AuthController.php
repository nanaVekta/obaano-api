<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * create a new AuthController instance.
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }

    /**
     * Register a new user.
     *
     * @param Request $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request){
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|min:2|max:100',
            'email' => 'required|string|email|max:100|unique:users',
            'phone' => 'required|string|min:10|max:10|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        if($validator->fails()) {
            return response()->json($validator->errors(), Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'phone' => $request->phone,
            'password' => Hash::make($request->password)
        ]);

        // return response()->json([
        //     'message' => 'User successfully registered',
        //     'data' => $user
        // ], Response::HTTP_CREATED);

        $password = $request->password;

        if(!$token = Auth::attempt(["email" => $request->email, 'password' => $password])){
            return response()->json(['message' => 'Unauthorized!', 'status' => 'error'], Response::HTTP_UNAUTHORIZED);
        }

        return $this->respondWithToken($token);

    }

    /**
     *
     * Set the role of user
     *
     * @param Request $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function setRole(Request $request) {
        $validator = Validator::make($request->all(), [
            'role_id' => 'required|integer',
        ]);

        if($validator->fails()) {
            $this->logout();
            return response()->json($validator->errors(), Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $user_id = Auth::user()->id;
        $user = User::find($user_id);
        $user->role_id = $request->role_id;
        $user->save();
        return response()->json(['message' => 'Role successfully set', 'status' => 'success'], Response::HTTP_OK);
    }

    /**
     *
     * Login user and create token
     *
     * @param Request $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request) {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        if (!$token = Auth::attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
        }

        return $this->respondWithToken($token);
    }


    /**
     * Logout user
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        Auth::logout();

        return response()->json(['message' => 'User successfully logged out.', 'status' => 'success'], Response::HTTP_OK);
    }

    /**
     *
     * Return a token response.
     *
     * @param mixed $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60,
            'user' => Auth::user()
        ], Response::HTTP_OK);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function profile()
    {
        return response()->json(Auth::user());
    }
}
