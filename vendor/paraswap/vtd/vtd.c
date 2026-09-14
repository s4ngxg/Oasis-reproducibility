#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include "include/lhp.h"
#include "include/util.h"
#include "include/sss.h"
#include "include/params.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <sodium.h>


#define SEC_PARAM 1024
#define CLOCK_PRECISION 1E9
#define MAX_SIZE 100
#define len 100
#define MAX_DIGITS 20
#define CLOCK_REALTIME 0
#define K 15
//range_proof_prover(&param, x, r, K, D + i * K, v, w, t, share_n);
void LHP_PGen_R ( LHP_puzzle_t* puzzle , LHP_param_t* pp , unsigned char* str, size_t s_size, mpz_t r)
{
	// gmp_randstate_t state;
	// gmp_randinit_default( state ) ;
	// gmp_randseed_ui ( state , rand() ) ;
	mpz_t s ;
	mpz_init_set_ui ( s , 0 ) ;
	for(int i = 0 ; i < s_size ; i++) {
		mpz_mul_ui ( s , s , 1 << 8 ) ;
		mpz_add_ui ( s , s , (uint8_t)str[i] ) ;
	}
	mpz_t N2 , temp ;
	//mpz_init ( r ) ;
	mpz_init ( N2 ) ;
	mpz_init ( temp ) ;
	mpz_pow_ui ( N2 , pp->N , 2 ) ;
	// mpz_urandomm ( r , state , N2 ) ;
	mpz_powm ( puzzle->u , pp->g , r , pp->N ) ;
	mpz_mul ( temp , r , pp->N ) ;
	mpz_powm ( puzzle->v , pp->h , temp , N2 ) ;
	mpz_add_ui ( temp , pp->N , 1 ) ;
	mpz_powm ( temp , temp , s , N2 ) ;
	mpz_mul ( puzzle->v , puzzle->v , temp ) ;
	mpz_mod ( puzzle->v , puzzle->v , N2 ) ;
	mpz_clear ( r ) ;
	mpz_clear ( N2 ) ;
	mpz_clear ( temp ) ;
	//gmp_randclear ( state );
}
void LHP_PGen_MPZ ( LHP_puzzle_t* puzzle , LHP_param_t* pp , mpz_t s, mpz_t r)
{
	
	mpz_t  N2 , temp ;
	mpz_init ( N2 ) ;
	mpz_init ( temp ) ;
	mpz_pow_ui ( N2 , pp->N , 2 ) ;
	mpz_powm ( puzzle->u , pp->g , r , pp->N ) ;
	mpz_mul ( temp , r , pp->N ) ;
	mpz_powm ( puzzle->v , pp->h , temp , N2 ) ;
	mpz_add_ui ( temp , pp->N , 1 ) ;
	mpz_powm ( temp , temp , s , N2 ) ;
	mpz_mul ( puzzle->v , puzzle->v , temp ) ;
	mpz_mod ( puzzle->v , puzzle->v , N2 ) ;
	//mpz_clear ( r ) ;
	mpz_clear ( N2 ) ;
	mpz_clear ( temp ) ;
}
typedef struct {
    mpz_t *v;
    mpz_t *w;
    char *t;
} RangeProof;

// int range_proof_verifier(LHP_param_t* parameter, mpz_t* x, mpz_t* w, char* t, LHP_puzzle_t* z,LHP_puzzle_t* D) {
//     int valid = 1;

//     mpz_t f[2];
//     mpz_t z_recompute[2];

//     for (int i = 0; i < share_n; i++) {
//         // 初始化
//         for (int j = 0; j < K; j++) {
//             mpz_init(f[j]);
//             mpz_init(z_recompute[j]);

//         // 计算 f_mid
//             mpz_t temp;
//             mpz_init(temp);
//             int odkk = i * K + j;
//             mpz_powm_ui(temp, z + i, t[i][j], parameter->N);  // z[j] ^ t[i]
//             mpz_mul(f[j], D + odkk, temp);            // d[i][j] * (z[j] ^ t[i])
//             mpz_mod(f[j], f[j], parameter->N);
//             mpz_clear(temp);

//             LHP_puzzle_t temp_puzzle;
//             LHP_init_puzzle(&temp_puzzle);
//             LHP_PGen(&temp_puzzle, parameter, v[i][j], mpz_sizeinbase(v[i][j], 10));
//             mpz_set(z_recompute[0], temp_puzzle.u);
//             mpz_set(z_recompute[1], temp_puzzle.v);

//         // 比较 f 和 z_recompute
//             for (int j = 0; j < 2; j++) {
//                 if (mpz_cmp(f[j], z_recompute[j]) != 0) {
//                     valid = 0;
//                     break;
//                 }
//             }
//         }

//         // 清除临时变量
//         for (int j = 0; j < 2; j++) {
//             mpz_clear(f[j]);
//             mpz_clear(z_recompute[j]);
//         }

//         LHP_clear_puzzle(&temp_puzzle);

//         if (valid == 0) break;
//     }

//     return valid;
// }

long long ttimer(void) {
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return (long long) (time.tv_sec * CLOCK_PRECISION + time.tv_nsec);
}


int main(){
    long long start_time, stop_time, total_time;
    int share_n =60;
    int share_t = 30;
    int count = 20;
    if (sodium_init() == -1) {
        printf("Error initializing libsodium\n");
        return 1;
    }
    int T = 100000;

    LHP_param_t param ;
    LHP_puzzle_t puzzle ;
    LHP_puzzle_t *puzzle_array ;
    LHP_puzzle_t dest_puzzle ;
    LHP_puzzle_sol_t solution ;

    LHP_puzzle_t *D_array ;
    D_array = malloc ( sizeof ( LHP_puzzle_t ) * share_n * K ) ;

    LHP_init_puzzle ( &dest_puzzle ) ;
    puzzle_array = malloc ( sizeof ( LHP_puzzle_t ) * share_n ) ;

    start_time = ttimer();
    LHP_init_param ( &param ) ;
    LHP_PSetup ( &param , SEC_PARAM , 1000000 ) ;
    stop_time = ttimer();
    total_time = stop_time - start_time;
    printf("\nSetup time: %.5f sec\n", total_time / CLOCK_PRECISION);


    sss_Share shares[share_n];

    OpenSSL_add_all_algorithms();
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        fprintf(stderr, "Error: Failed to create ECC key pair.\n");
        return 1;
    }

    // 生成 ECC 密钥对
    if (!EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "Error: Failed to generate ECC key pair.\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    // 获取 ECC 私钥
    const BIGNUM *priv_key = EC_KEY_get0_private_key(ec_key);
    // 获取 ECC 公钥
    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);

    char *priv_key_hex = BN_bn2hex(priv_key);

    start_time = ttimer();
    sss_create_shares(shares, priv_key_hex, share_n, share_t) ;
    stop_time = ttimer();
    total_time = stop_time -start_time;
    printf("\nSecret sharing time: %.5f sec\n", total_time / CLOCK_PRECISION);

    mpz_t x[share_n], r[share_n];
    mpz_t N2;
    mpz_init ( N2 ) ;
    mpz_pow_ui( N2 , param.N , 2 ) ;


    for (int i = 0; i < share_n; i++) {
        mpz_init_set_str(x[i], shares[i], 10); // Example initialization, convert shares[i] to mpz_t
        //mpz_init_set_ui(r[i], r_puzzle[i]);
    }
    float runtime[3][count];
    for(int cishu = 0; cishu < count; cishu++){                                 
        start_time = ttimer();
        for(int i = 0; i < share_n; i++){
            //size_t input_size = strlen(shares[i]);
            gmp_randstate_t state;
            gmp_randinit_default(state);
            gmp_randseed_ui(state, rand());
            mpz_init(r[i]);
            mpz_urandomm(r[i], state, N2);
            LHP_init_puzzle ( puzzle_array + i ) ;
            LHP_PGen_MPZ(puzzle_array + i, &param, x[i], r[i]);
            gmp_randclear(state);
                //r[i] = rand() % nint + 1;
                //LHP_PGen_R(puzzle_array + i, &param, shares[i], input_size, r[i]);
                //LHP_PGen(puzzle_array + i, &param, shares[i], input_size);
        }
        stop_time = ttimer();
        total_time = stop_time -start_time;
        //printf("\nTLP time: %.5f sec\n", total_time / CLOCK_PRECISION  );
        runtime[0][cishu] = total_time / CLOCK_PRECISION ;

        
    // Generate range proofs for each share
        mpz_t v[share_n][K], w[share_n][K];
        int t[share_n][K];
        mpz_t r_range[share_n][K];


        //RangeProof pis[share_n];
        //pis = malloc(share_n * sizeof(RangeProof));
        

        // LHP_puzzle_t D[share_n][K]; // Array to hold the puzzles for range proofs

        // // Generate range proofs for each share
        // for (int i = 0; i < share_n; i++) {
        //     range_proof_prover(&param, x, r, K, D[i], v, w, t, share_n);

        // }
        start_time = ttimer();
        for (int i = 0; i < share_n; i++) {
            //需要D t v w
            //range_proof_prover(&param, x[i], r[i], K, D + (i * K), v, w, t);
            gmp_randstate_t state;
            gmp_randinit_default(state);
            gmp_randseed_ui(state, rand());

            for (int j = 0; j < K; j++) {
                // Generate y[j]
                mpz_t y;
                mpz_init(y);
                mpz_urandomm(y, state, param.N);
                mpz_fdiv_q_ui(y, y, 2);
                //gmp_printf("y= %Zd\n",y);

                // Generate r_range[j]
                mpz_init(r_range[i][j]);
                mpz_urandomm(r_range[i][j], state, param.N);

                //gmp_printf("r_range[%d][%d]= %Zd\n",i, j, r_range[i][j]);

                int odk= i * K +j;
                LHP_init_puzzle ( D_array + odk ) ;
                LHP_PGen_MPZ(D_array + odk, &param, y, r_range[i][j]);
                //LHP_PGen_MPZ(D , &param, y);
                //LHP_PGen(D + K, param, (unsigned char*) mpz_get_str(NULL, 10, y), mpz_sizeinbase(y, 10));

                // Generate t[j] randomly as 0 or 1
                t[i][j] = (rand() % 2);
                //printf("t[%d][%d] = %d\n", i, j, t[i][j]);
                // Compute v[j] = y[j] * (x[i] ^ t[j])
                // Compute v[j] = y[j] + (x[i] * t[j])
                mpz_init(v[i][j]);
                mpz_init(w[i][j]);
                // gmp_printf("v[%d][%d]= %Zd\n",i, j, v[i][j]);
                // gmp_printf("w[%d][%d]= %Zd\n",i, j, w[i][j]);
                if (t[i][j] == 1) {
                    //mpz_mul(v[i][j], y, x[i]);
                    mpz_add(v[i][j], y, x[i]);
                    mpz_add(w[i][j],r_range[i][j], r[i]);
                } else {
                    mpz_set(v[i][j], y);
                    mpz_set(w[i][j], r_range[i][j]);
                    // gmp_printf("v[%d][%d]= %Zd\n",i, j, v[i][j]);
                    
                    // gmp_printf("w[%d][%d]= %Zd\n",i, j, w[i][j]);
                    // char *temp_str = NULL;
                    // temp_str = mpz_get_str(NULL, 10, w[i][j]);
                    // printf("w[i][j]: %s\n", temp_str);
                }

                // Compute w[j] = r_range[j] + t[j] * r[i]
                

                // Clear temporary variables
                mpz_clear(y);

            }
            //pis[i] = {v,w,t};

            gmp_randclear(state);

        }
        stop_time = ttimer();
        total_time = stop_time -start_time;
        //printf("\nRange proof time: %.5f sec\n", total_time / CLOCK_PRECISION);
        runtime[1][cishu] = total_time / CLOCK_PRECISION ;


        start_time = ttimer();
        int valid = 1;

        //mpz_t z_recompute[2];
        for (int i = 0; i < share_n; i++) {
            // 初始化
            for (int j = 0; j < K; j++) {

            // 计算 f_mid
                int odkk = i * K + j;

                LHP_puzzle_t *puzzle_temp_Z;
                puzzle_temp_Z = malloc ( sizeof ( LHP_puzzle_t ) ) ;
                LHP_init_puzzle ( puzzle_temp_Z ) ;
                puzzle_temp_Z = puzzle_array + i;

                LHP_puzzle_t *puzzle_temp_D;
                puzzle_temp_D = malloc ( sizeof ( LHP_puzzle_t ) ) ;
                LHP_init_puzzle ( puzzle_temp_D ) ;
                puzzle_temp_D = D_array + odkk;
                
                LHP_puzzle_t *puzzle_temp_F;
                puzzle_temp_F = malloc ( sizeof ( LHP_puzzle_t ) ) ;
                LHP_init_puzzle ( puzzle_temp_F ) ;
                //LHP_init_puzzle(puzzle_temp_F);

                // char *temp_str = NULL;
                // temp_str = mpz_get_str(NULL, 10, puzzle_temp_D->u);
                // printf("puzzle_temp_D->u: %s\n", temp_str);

                // gmp_printf("puzzle_temp_D->u: %Zd\n", puzzle_temp_D->u);
                // gmp_printf("puzzle_temp_F->u: %Zd\n", puzzle_temp_F->u);
                // mpz_powm_ui(temp1, puzzle_temp_Z->u, t[i][j], param.N);  // z[j] ^ t[i]
                // mpz_powm_ui(temp2, puzzle_temp_Z->v, t[i][j], param.N);
                if (t[i][j] == 1) {
                    //mpz_mul(v[i][j], y, x[i]);
                    mpz_mul((puzzle_temp_F)->u, puzzle_temp_D->u, puzzle_temp_Z->u);
                    mpz_mul((puzzle_temp_F)->v, puzzle_temp_D->v, puzzle_temp_Z->v);
                } else {
                    // LHP_puzzle_t *dest_puzzle;
                    // LHP_init_puzzle ( dest_puzzle ) ;
                    // mpz_init_set_ui ( dest_puzzle -> u , 1 ) ;
                    //mpz_mul((puzzle_temp_F)->u, puzzle_temp_D->u, dest_puzzle -> u);
                    mpz_set((puzzle_temp_F)->u, puzzle_temp_D->u);
                    //puzzle_temp_F->u  = puzzle_temp_D->u;
                    mpz_set((puzzle_temp_F)->v, puzzle_temp_D->v);

                    // mpz_set((puzzle_temp_F)->u, D_array[i].u);
                    // mpz_set((puzzle_temp_F)->v, puzzle_temp_D->v);
                    // gmp_printf("D_array->u: %Zd\n", D_array[i].u);
                    // gmp_printf("puzzle_temp_D->u: %Zd\n", puzzle_temp_D->u);  // 应输出 12345
                    // gmp_printf("puzzle_temp_F->u: %Zd\n", puzzle_temp_F->u); 
                    
                }
                // mpz_mul(temp1, puzzle_temp_Z->u, t[i][j]);  // z[j] ^ t[i]
                // mpz_mul(temp2, puzzle_temp_Z->v, t[i][j]);
                // mpz_mul((&puzzle_temp_F)->u, puzzle_temp_D->u, temp1);            // D[i][j] * (z[j] ^ t[i])
                // mpz_mul((&puzzle_temp_F)->v, puzzle_temp_D->v, temp2); 
                mpz_mod((puzzle_temp_F)->u, (puzzle_temp_F)->u, param.N);
                mpz_mod((puzzle_temp_F)->v, (puzzle_temp_F)->v, N2);
                
                // gmp_printf("puzzle_temp_D->u: %Zd\n", puzzle_temp_D->u);
                // gmp_printf("puzzle_temp_F->u: %Zd\n", puzzle_temp_F->u);

                LHP_puzzle_t *temp_puzzle_F;
                temp_puzzle_F = malloc ( sizeof ( LHP_puzzle_t ) ) ;
                LHP_init_puzzle(temp_puzzle_F);
                LHP_PGen_MPZ(temp_puzzle_F, &param, v[i][j],w[i][j]);
                //gmp_printf("temp_puzzle_F->u: %Zd\n", temp_puzzle_F->u);

                if (mpz_cmp((puzzle_temp_F)->u, temp_puzzle_F->u) != 0) {
                    valid = 0;
                    break;
                }
                if (mpz_cmp((puzzle_temp_F)->v, temp_puzzle_F->v) != 0) {
                    valid = 0;
                    break;
                }
            }

            // 清除临时变量
            // mpz_clear(z_recompute[0]);
            // mpz_clear(z_recompute[1]);
            

            if (valid == 0) {
                printf("Verify error.\n");
                break;
            }
        }
        stop_time = ttimer();
        total_time = stop_time -start_time;
       
        printf("\nVerify time: %.5f sec\n", total_time / CLOCK_PRECISION);
        runtime[2][cishu] = total_time / CLOCK_PRECISION ;
    }


    float TLP_time=0, Range_proof_time=0, Verify_time=0;
    for(int cishu = 0; cishu < count ;cishu++){
        TLP_time += runtime[0][cishu];
        Range_proof_time += runtime[1][cishu];
        Verify_time += runtime[2][cishu];
    }
    printf("\nTLP_time: %.5f sec\n", TLP_time / count);
    printf("\nRange_proof_time: %.5f sec\n", Range_proof_time / count);
    printf("\nVerify_time: %.5f sec\n", Verify_time / count);
    // Clear mpz_t variables
    // for (int i = 0; i < share_n; i++) {
    //     mpz_clear(x[i]);
    //     mpz_clear(r[i]);
    //     for(int j = 0; j < K; j++){
    //     mpz_clear(v[i][j]);
    //     mpz_clear(w[i][j]);
    //     //mpz_clear(t[i][j]);
    //     }
    // }

    EC_KEY_free(ec_key);
    free(D_array);
    free(puzzle_array);
    return 0;
}



// Created by nono on 2024/5/16.
//
