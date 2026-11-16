// ============================================================================
//  orbit.cpp   ——   Physics 307, leapfrog N-body + anim-style 3D graphics
//
//  Simulates gravitating bodies with the leapfrog (drift-kick-drift) scheme
//  from the homework, and renders them into a rotating, tick-marked 3D
//  coordinate box with trailing orbits and a live energy readout — the same
//  look the course `anim` tool produces.
//
//  Units:  distance = AU,  mass = solar masses,  time = years   =>   GM_sun = 4*pi^2
//
//  Build:   g++ -O2 -std=c++17 orbit.cpp -o orbit
//  Run:     ./orbit              # writes frames/frame_XXXX.ppm  (self-rendered)
//           ./orbit anim | anim  # instead emits course anim commands (c3/ct3/T)
//
//  The physics and the renderer are completely independent of any library;
//  only the C++ standard library is used.
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <algorithm>

static const double PI  = 3.14159265358979323846;
static const double TAU = 2.0 * PI;
static const double GM  = 4.0 * PI * PI;          // G with M_sun = 1

// ----------------------------------------------------------------------------
//  vector math
// ----------------------------------------------------------------------------
struct Vec3 {
    double x=0, y=0, z=0;
    Vec3() {}
    Vec3(double a,double b,double c):x(a),y(b),z(c){}
    Vec3 operator+(const Vec3&o)const{return {x+o.x,y+o.y,z+o.z};}
    Vec3 operator-(const Vec3&o)const{return {x-o.x,y-o.y,z-o.z};}
    Vec3 operator*(double s)const{return {x*s,y*s,z*s};}
};
static double norm(const Vec3&v){return std::sqrt(v.x*v.x+v.y*v.y+v.z*v.z);}

// ----------------------------------------------------------------------------
//  bodies
// ----------------------------------------------------------------------------
struct Body {
    double m;
    Vec3 s, v, a;                 // position, velocity, acceleration
    uint8_t col[3];               // draw colour
    double radius;                // draw radius (px)
    std::vector<Vec3> trail;      // recorded path
    size_t trail_cap;
};

std::vector<Body> bodies;

// accelerations: a_i = sum_j  GM m_j (s_j - s_i) / |s_j - s_i|^3
void compute_accel() {
    for (auto& b : bodies) b.a = {0,0,0};
    for (size_t i=0;i<bodies.size();++i)
        for (size_t j=0;j<bodies.size();++j) {
            if (i==j) continue;
            Vec3 d = bodies[j].s - bodies[i].s;
            double r = norm(d);
            if (r < 1e-9) r = 1e-9;
            double c = GM * bodies[j].m / (r*r*r);
            bodies[i].a = bodies[i].a + d * c;
        }
}

// leapfrog:  drift dt/2  ->  kick dt  ->  drift dt/2   (exactly the HW6 recipe)
void leapfrog(double dt) {
    for (auto& b : bodies) b.s = b.s + b.v * (dt*0.5);
    compute_accel();
    for (auto& b : bodies) b.v = b.v + b.a * dt;
    for (auto& b : bodies) b.s = b.s + b.v * (dt*0.5);
}

double total_energy() {
    double ke=0, pe=0;
    for (auto& b : bodies) ke += 0.5*b.m*(b.v.x*b.v.x+b.v.y*b.v.y+b.v.z*b.v.z);
    for (size_t i=0;i<bodies.size();++i)
        for (size_t j=i+1;j<bodies.size();++j)
            pe -= GM*bodies[i].m*bodies[j].m / norm(bodies[i].s-bodies[j].s);
    return ke+pe;
}

// zero the total momentum so the centre of mass does not drift off screen
void zero_momentum() {
    double M=0; Vec3 p{0,0,0};
    for (auto& b : bodies){ M+=b.m; p = p + b.v*b.m; }
    Vec3 vc = p*(1.0/M);
    for (auto& b : bodies) b.v = b.v - vc;
}
// tilt the whole configuration about the x-axis (gives an inclined orbit plane)
void incline(double ang) {
    double c=std::cos(ang), s=std::sin(ang);
    for (auto& b : bodies) {
        double y=b.s.y, z=b.s.z; b.s.y=y*c-z*s; b.s.z=y*s+z*c;
        double vy=b.v.y, vz=b.v.z; b.v.y=vy*c-vz*s; b.v.z=vy*s+vz*c;
    }
}

// ----------------------------------------------------------------------------
//  scene: a hierarchical triple — a tight inner pair plus a distant third body
//  on an inclined orbit.  (This is the system in the reference screenshot;
//  swap in circular / elliptical initial conditions for the HW5 parts.)
// ----------------------------------------------------------------------------
void build_triple() {
    bodies.clear();
    const double mi=0.5, din=0.36;                 // inner pair
    const double mo=0.5, dout=2.2;                 // outer body
    const double Mp=2*mi, Mt=Mp+mo;
    const double vin  = std::sqrt(GM*(2*mi)/din);          // inner mutual speed
    const double vout = std::sqrt(GM*Mt/dout)*0.9;         // outer orbital speed
    const double Ppy=-dout*mo/Mt, P3y=dout*Mp/Mt;
    const double Vpx= vout*mo/Mt, V3x=-vout*Mp/Mt;

    auto add=[&](Vec3 s,Vec3 v,double m,uint8_t r,uint8_t g,uint8_t b,double rad,size_t cap){
        Body B; B.m=m; B.s=s; B.v=v; B.col[0]=r; B.col[1]=g; B.col[2]=b;
        B.radius=rad; B.trail_cap=cap; bodies.push_back(B);
    };
    add({-din/2,Ppy,0}, {Vpx,-vin*0.5,0}, mi,  90,240,120, 6, 2200);  // inner a (green)
    add({ din/2,Ppy,0}, {Vpx, vin*0.5,0}, mi,  95,155,255, 6, 2200);  // inner b (blue)
    add({ 0,    P3y,0}, {V3x, 0,      0}, mo, 255,150, 70, 8, 1600);  // outer   (orange)

    incline(30*PI/180.0);
    zero_momentum();
}

// ----------------------------------------------------------------------------
//  --- 3D framebuffer renderer (no external libraries) ---
// ----------------------------------------------------------------------------
const int   W = 720, H = 720;
const double VIEWR = 2.8;                 // half-extent of the drawn box (AU)
double PITCH = 22.0*PI/180.0;             // camera tilt (flattens the plane)
double yaw   = 0.7;                        // camera spin (advanced each frame)

std::vector<uint8_t> fb(W*H*3);

void clear_fb(){ std::fill(fb.begin(), fb.end(), 4); }   // near-black

inline void blend(int x,int y,const uint8_t c[3],double a){
    if(x<0||x>=W||y<0||y>=H) return;
    int i=(y*W+x)*3;
    for(int k=0;k<3;++k) fb[i+k]=(uint8_t)std::min(255.0, fb[i+k]*(1-a)+c[k]*a);
}

struct P2{ double sx, sy, depth; };
P2 project(const Vec3& p){
    double cA=std::cos(yaw), sA=std::sin(yaw), cP=std::cos(PITCH), sP=std::sin(PITCH);
    double xa=p.x*cA - p.y*sA, ya=p.x*sA + p.y*cA, za=p.z;
    double xb=xa, yb=ya*cP - za*sP, zb=ya*sP + za*cP;
    double sc=std::min(W,H)/(2*VIEWR*1.6);
    return { W/2 + xb*sc, H/2 - zb*sc, yb };
}

void line(P2 A, P2 B, const uint8_t c[3], double a){
    int x0=(int)std::lround(A.sx), y0=(int)std::lround(A.sy);
    int x1=(int)std::lround(B.sx), y1=(int)std::lround(B.sy);
    int dx=std::abs(x1-x0), dy=-std::abs(y1-y0);
    int sx=x0<x1?1:-1, sy=y0<y1?1:-1, err=dx+dy;
    while(true){
        blend(x0,y0,c,a);
        if(x0==x1&&y0==y1) break;
        int e2=2*err;
        if(e2>=dy){ err+=dy; x0+=sx; }
        if(e2<=dx){ err+=dx; y0+=sy; }
    }
}
void disk(P2 p,double r,const uint8_t c[3]){
    int cx=(int)std::lround(p.sx), cy=(int)std::lround(p.sy), R=(int)std::ceil(r);
    for(int dy=-R;dy<=R;++dy)for(int dx=-R;dx<=R;++dx){
        double d=std::sqrt(dx*dx+dy*dy);
        if(d<=r) blend(cx+dx,cy+dy,c, d>r-1.3?0.5:1.0);
    }
}

// --- minimal 5x7 bitmap font (only the glyphs this program prints) ---
std::unordered_map<char,std::array<std::string,7>> FONT;
void init_font(){
    auto g=[&](char ch,std::initializer_list<const char*> rows){
        std::array<std::string,7> a; int i=0; for(auto r:rows) a[i++]=r; FONT[ch]=a; };
    g(' ',{".....",".....",".....",".....",".....",".....","....."});
    g('0',{".###.","#...#","#..##","#.#.#","##..#","#...#",".###."});
    g('1',{"..#..",".##..","..#..","..#..","..#..","..#..",".###."});
    g('2',{".###.","#...#","....#","...#.","..#..",".#...","#####"});
    g('3',{"#####","...#.","..#..","...#.","....#","#...#",".###."});
    g('4',{"...#.","..##.",".#.#.","#..#.","#####","...#.","...#."});
    g('5',{"#####","#....","####.","....#","....#","#...#",".###."});
    g('6',{".###.","#....","#....","####.","#...#","#...#",".###."});
    g('7',{"#####","....#","...#.","..#..",".#...",".#...",".#..."});
    g('8',{".###.","#...#","#...#",".###.","#...#","#...#",".###."});
    g('9',{".###.","#...#","#...#",".####","....#","....#",".###."});
    g('A',{".###.","#...#","#...#","#####","#...#","#...#","#...#"});
    g('C',{".####","#....","#....","#....","#....","#....",".####"});
    g('E',{"#####","#....","#....","####.","#....","#....","#####"});
    g('G',{".####","#....","#....","#.###","#...#","#...#",".###."});
    g('L',{"#....","#....","#....","#....","#....","#....","#####"});
    g('N',{"#...#","##..#","#.#.#","#.#.#","#..##","#...#","#...#"});
    g('O',{".###.","#...#","#...#","#...#","#...#","#...#",".###."});
    g('R',{"####.","#...#","#...#","####.","#.#..","#..#.","#...#"});
    g('T',{"#####","..#..","..#..","..#..","..#..","..#..","..#.."});
    g('U',{"#...#","#...#","#...#","#...#","#...#","#...#",".###."});
    g('Y',{"#...#","#...#",".#.#.","..#..","..#..","..#..","..#.."});
    g('-',{".....",".....",".....","#####",".....",".....","....."});
    g('+',{".....","..#..","..#..","#####","..#..","..#..","....."});
    g('.',{".....",".....",".....",".....",".....",".##..",".##.."});
    g(':',{".....",".##..",".##..",".....",".##..",".##..","....."});
}
void text(int x,int y,const std::string& s,int sz,const uint8_t c[3]){
    for(char raw: s){
        char ch=std::toupper((unsigned char)raw);
        auto it=FONT.find(ch); if(it==FONT.end()){ x+=6*sz; continue; }
        for(int r=0;r<7;++r)for(int col=0;col<5;++col)
            if(it->second[r][col]=='#')
                for(int a=0;a<sz;++a)for(int b=0;b<sz;++b) blend(x+col*sz+a,y+r*sz+b,c,1.0);
        x+=6*sz;
    }
}

// --- draw the rotating coordinate box: faint cube, axes, ticks, labels ---
void draw_grid(){
    const uint8_t cbox[3]={55,66,92}, cax[3]={120,136,168}, ctick[3]={150,166,196};
    const uint8_t clab[3]={150,170,208}, camb[3]={246,169,74};
    double R=VIEWR;
    Vec3 corner[8]; int n=0;
    for(int i=0;i<2;++i)for(int j=0;j<2;++j)for(int k=0;k<2;++k)
        corner[n++]={i?R:-R, j?R:-R, k?R:-R};
    int E[12][2]={{0,1},{1,3},{3,2},{2,0},{4,5},{5,7},{7,6},{6,4},{0,4},{1,5},{2,6},{3,7}};
    for(auto&e:E) line(project(corner[e[0]]), project(corner[e[1]]), cbox, 0.9);

    struct Ax{ Vec3 u, t; char name; };
    Ax axes[3]={ {{1,0,0},{0,0,1},'X'}, {{0,1,0},{0,0,1},'Y'}, {{0,0,1},{1,0,0},'Z'} };
    double step=1.0, tl=R*0.03;
    for(auto&ax:axes){
        line(project(ax.u*(-R)), project(ax.u*R), cax, 1.0);
        for(double v=-2; v<=2.0001; v+=step){
            Vec3 base=ax.u*v;
            line(project(base-ax.t*tl), project(base+ax.t*tl), ctick, 1.0);
            if(std::fabs(v)>1e-9){
                P2 lp=project(base-ax.t*(tl*3.6));
                char buf[16]; std::snprintf(buf,sizeof buf,"%g",v);
                text((int)lp.sx-3,(int)lp.sy-3,buf,1,clab);
            }
        }
        P2 nb=project(ax.u*(R*1.10));
        text((int)nb.sx-2,(int)nb.sy-3, std::string(1,ax.name),1,camb);
    }
}

void render(double E){
    clear_fb();
    draw_grid();
    // trails
    for(auto&b: bodies)
        for(size_t i=1;i<b.trail.size();++i)
            line(project(b.trail[i-1]), project(b.trail[i]), b.col, 0.55);
    // bodies, far ones first
    std::vector<size_t> order(bodies.size());
    for(size_t i=0;i<order.size();++i) order[i]=i;
    std::sort(order.begin(),order.end(),
              [&](size_t a,size_t b){ return project(bodies[a].s).depth < project(bodies[b].s).depth; });
    for(size_t idx: order){
        P2 p=project(bodies[idx].s);
        uint8_t glow[3]={ (uint8_t)(bodies[idx].col[0]/2+30),
                          (uint8_t)(bodies[idx].col[1]/2+30),
                          (uint8_t)(bodies[idx].col[2]/2+30) };
        disk(p, bodies[idx].radius*1.8, glow);
        disk(p, bodies[idx].radius, bodies[idx].col);
    }
    // energy readout (top-left), matching the anim `T` overlay
    char buf[64]; std::snprintf(buf,sizeof buf,"TOTAL CURRENT ENERGY: %.6E", E);
    const uint8_t white[3]={230,236,248};
    text(24,22,buf,2,white);
}

void write_ppm(const char* path){
    FILE* f=std::fopen(path,"wb");
    std::fprintf(f,"P6\n%d %d\n255\n",W,H);
    std::fwrite(fb.data(),1,fb.size(),f);
    std::fclose(f);
}

// ----------------------------------------------------------------------------
//  anim-command output (for piping into the course `anim` tool)
//  Uses exactly the commands documented in the homework:  c3, ct3, T
// ----------------------------------------------------------------------------
void emit_anim_frame(double E){
    for(size_t i=0;i<bodies.size();++i){
        const Vec3&s=bodies[i].s;
        std::printf("ct3 %zu %g %g %g %g\n", i, s.x, s.y, s.z, bodies[i].radius*0.01);
    }
    std::printf("T 0.9 -0.9\n");
    std::printf("Total Current Energy: %e\n", E);
    std::printf("F\n");            // <-- frame terminator; adjust to your anim if different
    std::fflush(stdout);
}

// ----------------------------------------------------------------------------
int main(int argc, char** argv){
    bool anim_mode = (argc>1 && std::strcmp(argv[1],"anim")==0);
    init_font();
    build_triple();

    const double dt = 2e-3;
    const int    frames = 240;
    const int    steps_per_frame = 10;

    for(int fr=0; fr<frames; ++fr){
        for(int k=0;k<steps_per_frame;++k){
            leapfrog(dt);
            for(auto&b: bodies){                    // record trail each step
                b.trail.push_back(b.s);
                if(b.trail.size()>b.trail_cap) b.trail.erase(b.trail.begin());
            }
        }
        double E = total_energy();
        if(anim_mode){
            emit_anim_frame(E);
        } else {
            yaw += TAU/frames;                      // one full turn over the run
            render(E);
            char path[64]; std::snprintf(path,sizeof path,"frames/frame_%04d.ppm",fr);
            write_ppm(path);
        }
    }
    if(!anim_mode)
        std::fprintf(stderr,"wrote %d frames to frames/  (final energy %.6e)\n",frames,total_energy());
    return 0;
}