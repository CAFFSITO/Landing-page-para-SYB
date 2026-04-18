"use client";

import { motion, type Variants } from "framer-motion";
import { ArrowDown } from "lucide-react";
import Link from "next/link";

const CAL_URL = process.env.NEXT_PUBLIC_CAL_URL ?? "#";

export default function Hero() {
  const containerVariants: Variants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.2,
      },
    },
  };

  const itemVariants: Variants = {
    hidden: { opacity: 0, y: 30 },
    show: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.8, ease: "easeOut" }
    },
  };

  return (
    <section className="relative w-full h-[100vh] flex flex-col items-center justify-center overflow-hidden bg-[#0D0618]">
      {/* Background radial gradient */}
      <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] md:w-[800px] md:h-[800px] bg-primary/30 rounded-full blur-[100px] md:blur-[140px]" />
      </div>

      <div className="relative z-10 max-w-5xl px-6 text-center">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true }}
          className="flex flex-col items-center"
        >
          <motion.h1
            variants={itemVariants}
            className="text-4xl md:text-5xl lg:text-[4rem] font-bold text-contrast tracking-tight mb-6 leading-[1.15]"
          >
            La mayoría de los dueños de negocio no tienen un problema de tiempo. <br className="hidden lg:block" />
            <span className="text-secondary">Tienen un problema de arquitectura.</span>
          </motion.h1>

          <motion.p
            variants={itemVariants}
            className="text-lg md:text-xl text-contrast/80 max-w-3xl mb-12 leading-relaxed font-light"
          >
            Nuestra metodología no instala herramientas. Elimina el techo estructural que hoy le pone un límite a tu crecimiento.
          </motion.p>

          <motion.div variants={itemVariants}>
            <Link
              href={CAL_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center px-8 py-4 text-lg font-bold text-contrast transition-all duration-200 rounded-md bg-gradient-to-r from-primary to-secondary hover:brightness-110 shadow-[0_4px_20px_rgba(157,92,192,0.4)]"
            >
              Agendá tu diagnóstico <span className="ml-2">&rarr;</span>
            </Link>
          </motion.div>
        </motion.div>
      </div>

      {/* Scroll indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5, duration: 1 }}
        className="absolute bottom-10 left-1/2 -translate-x-1/2 flex flex-col items-center text-contrast/60"
      >
        <motion.div
          animate={{ y: [0, 8, 0] }}
          transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
        >
          <ArrowDown className="w-6 h-6 text-secondary/80" />
        </motion.div>
      </motion.div>
    </section>
  );
}
